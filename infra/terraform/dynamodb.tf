# Incident journal. The key schema must match src/storage/dynamodb_store.py.
resource "aws_dynamodb_table" "incidents" {
  name         = "${local.prefix}-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  # "high severity in the last 7 days" is one Query on this index, not a table Scan.
  global_secondary_index {
    name            = "severity-timestamp-index"
    hash_key        = "severity"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = var.incident_retention_days > 0
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }
}
