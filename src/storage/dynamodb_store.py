"""DynamoDB incident journal for the AWS mode.

Table layout (kept in sync with infra/terraform/dynamodb.tf):

* partition key ``incident_id`` (S)
* global secondary index ``severity-timestamp-index``: partition key ``severity``,
  sort key ``timestamp``. A "high severity in the last 7 days" query is a single
  key-condition Query on the index instead of a table Scan.
* optional TTL attribute ``expires_at`` (epoch seconds) for retention.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from decimal import Decimal
from typing import Any

from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from src.engine.models import SEVERITY_LABELS
from src.incident import Incident

from .base import DEFAULT_QUERY_LIMIT

SEVERITY_INDEX = "severity-timestamp-index"
TTL_ATTRIBUTE = "expires_at"


def create_incident_table(client: Any, table_name: str) -> None:
    """Create the incident table with the same key schema as the Terraform module."""
    client.create_table(
        TableName=table_name,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "incident_id", "AttributeType": "S"},
            {"AttributeName": "severity", "AttributeType": "S"},
            {"AttributeName": "timestamp", "AttributeType": "S"},
        ],
        KeySchema=[{"AttributeName": "incident_id", "KeyType": "HASH"}],
        GlobalSecondaryIndexes=[
            {
                "IndexName": SEVERITY_INDEX,
                "KeySchema": [
                    {"AttributeName": "severity", "KeyType": "HASH"},
                    {"AttributeName": "timestamp", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )


def _plain(value: Any) -> Any:
    """Convert DynamoDB Decimals back into ints/floats for JSON output."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_plain(item) for item in value]
    return value


class DynamoDbIncidentStore:
    def __init__(self, table: Any, retention_days: int = 0) -> None:
        """``table`` is a boto3 ``dynamodb.Table``; ``retention_days`` > 0 sets a TTL."""
        self.table = table
        self.retention_days = retention_days

    @classmethod
    def from_table_name(
        cls, table_name: str, *, retention_days: int = 0, resource: Any = None
    ) -> DynamoDbIncidentStore:
        if resource is None:
            import boto3

            resource = boto3.resource("dynamodb")
        return cls(resource.Table(table_name), retention_days)

    def add(self, incident: Incident) -> bool:
        item = incident.to_dict()
        if self.retention_days > 0:
            logged = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
            item[TTL_ATTRIBUTE] = int(logged.timestamp()) + self.retention_days * 86400
        try:
            self.table.put_item(Item=item, ConditionExpression=Attr("incident_id").not_exists())
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise
        return True

    def exists(self, incident_id: str) -> bool:
        response = self.table.get_item(
            Key={"incident_id": incident_id},
            ConsistentRead=True,
            ProjectionExpression="incident_id",
        )
        return "Item" in response

    def query(
        self,
        *,
        severities: Sequence[str] | None = None,
        since: str | None = None,
        rule: str | None = None,
        limit: int = DEFAULT_QUERY_LIMIT,
    ) -> list[dict[str, Any]]:
        incidents: list[dict[str, Any]] = []
        for severity in severities or SEVERITY_LABELS:
            incidents.extend(self._query_severity(severity, since, rule, limit))
        incidents.sort(key=lambda incident: incident["timestamp"], reverse=True)
        return incidents[:limit]

    def _query_severity(
        self, severity: str, since: str | None, rule: str | None, limit: int
    ) -> list[dict[str, Any]]:
        condition = Key("severity").eq(severity)
        if since:
            condition = condition & Key("timestamp").gte(since)
        kwargs: dict[str, Any] = {
            "IndexName": SEVERITY_INDEX,
            "KeyConditionExpression": condition,
            "ScanIndexForward": False,
        }
        if rule:
            kwargs["FilterExpression"] = Attr("rule").eq(rule)

        found: list[dict[str, Any]] = []
        while len(found) < limit:
            response = self.table.query(**kwargs)
            for item in response.get("Items", []):
                item.pop(TTL_ATTRIBUTE, None)
                found.append(_plain(item))
            if "LastEvaluatedKey" not in response:
                break
            kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
        return found[:limit]
