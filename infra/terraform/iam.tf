data "aws_iam_policy_document" "detector_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "detector" {
  name               = "${local.prefix}-detector"
  description        = "Execution role of the DLP detector function"
  assume_role_policy = data.aws_iam_policy_document.detector_trust.json
}

# Least privilege: IAM denies everything that is not listed, and a few explicit Deny
# statements below keep the role harmless even if someone later widens the Allow list.
data "aws_iam_policy_document" "detector" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.detector.arn}:*"]
  }

  statement {
    sid = "ReadAndTagMonitoredObjects"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetObjectTagging",
      "s3:GetObjectVersionTagging",
      "s3:PutObjectTagging",
      "s3:PutObjectVersionTagging",
    ]
    resources = local.monitored_object_arns
  }

  # Deleting the original is the second half of "move to quarantine".
  dynamic "statement" {
    for_each = var.enable_quarantine ? [1] : []

    content {
      sid       = "RemoveQuarantinedOriginals"
      actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
      resources = local.monitored_object_arns
    }
  }

  # ListBucket makes S3 answer NoSuchKey instead of AccessDenied for a vanished object.
  statement {
    sid = "InspectMonitoredBuckets"
    actions = [
      "s3:ListBucket",
      "s3:GetBucketAcl",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketPublicAccessBlock",
    ]
    resources = local.monitored_bucket_arns
  }

  dynamic "statement" {
    for_each = var.enable_quarantine ? [1] : []

    content {
      sid       = "WriteToQuarantine"
      actions   = ["s3:PutObject", "s3:PutObjectTagging", "s3:AbortMultipartUpload"]
      resources = local.quarantine_object_arns
    }
  }

  # GetItem backs the idempotency check, PutItem writes the (append-only) journal.
  statement {
    sid       = "JournalIncidents"
    actions   = ["dynamodb:PutItem", "dynamodb:GetItem"]
    resources = [aws_dynamodb_table.incidents.arn]
  }

  statement {
    sid       = "PublishAlerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  dynamic "statement" {
    for_each = var.sns_kms_key_id == null ? [] : [1]

    content {
      sid       = "UseAlertTopicKey"
      actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
      resources = [startswith(var.sns_kms_key_id, "arn:") ? var.sns_kms_key_id : "arn:${local.partition}:kms:${var.aws_region}:${local.account_id}:key/${var.sns_kms_key_id}"]
    }
  }

  statement {
    sid       = "DeadLetterFailedEvents"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dead_letter.arn]
  }

  # --- explicit denies -------------------------------------------------------------------

  # The journal is evidence: the detector may add incidents but never alter or remove them.
  statement {
    sid    = "DenyJournalTampering"
    effect = "Deny"
    actions = [
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:UpdateTable",
      "dynamodb:DeleteTable",
    ]
    resources = [aws_dynamodb_table.incidents.arn, "${aws_dynamodb_table.incidents.arn}/index/*"]
  }

  statement {
    sid           = "DenyS3OutsideScope"
    effect        = "Deny"
    actions       = ["s3:*"]
    not_resources = local.s3_allowed_arns
  }

  dynamic "statement" {
    for_each = var.enable_quarantine ? [1] : []

    content {
      sid    = "DenyQuarantineTampering"
      effect = "Deny"
      actions = [
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutBucketPolicy",
        "s3:PutLifecycleConfiguration",
      ]
      resources = [local.quarantine_bucket_arn, "${local.quarantine_bucket_arn}/*"]
    }
  }
}

resource "aws_iam_role_policy" "detector" {
  name   = "detector"
  role   = aws_iam_role.detector.id
  policy = data.aws_iam_policy_document.detector.json
}

# For analysts running `cli.py incident-log query --backend dynamodb`. Not attached to
# anyone: attach it to the people or roles that should read the journal.
data "aws_iam_policy_document" "incident_reader" {
  statement {
    actions = ["dynamodb:Query", "dynamodb:DescribeTable"]
    resources = [
      aws_dynamodb_table.incidents.arn,
      "${aws_dynamodb_table.incidents.arn}/index/severity-timestamp-index",
    ]
  }
}

resource "aws_iam_policy" "incident_reader" {
  name        = "${local.prefix}-incident-reader"
  description = "Read-only access to the DLP incident journal"
  policy      = data.aws_iam_policy_document.incident_reader.json
}
