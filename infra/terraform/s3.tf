# ---------------------------------------------------------------------------------------
# Monitored bucket: every upload triggers the detector.
# ---------------------------------------------------------------------------------------

resource "aws_s3_bucket" "outbound" {
  bucket        = local.outbound_bucket_name
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_public_access_block" "outbound" {
  bucket                  = aws_s3_bucket.outbound.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "outbound" {
  bucket = aws_s3_bucket.outbound.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "outbound" {
  bucket = aws_s3_bucket.outbound.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "outbound" {
  dynamic "statement" {
    for_each = var.enforce_tls ? [1] : []

    content {
      sid       = "DenyInsecureTransport"
      effect    = "Deny"
      actions   = ["s3:*"]
      resources = [aws_s3_bucket.outbound.arn, "${aws_s3_bucket.outbound.arn}/*"]

      principals {
        type        = "*"
        identifiers = ["*"]
      }

      condition {
        test     = "Bool"
        variable = "aws:SecureTransport"
        values   = ["false"]
      }
    }
  }

  # "Block" in AWS means tag + deny: the detector runs after the object already exists, so
  # it marks the object and this policy makes it unreadable for everyone but the detector.
  statement {
    sid       = "DenyReadOfBlockedObjects"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.outbound.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:ExistingObjectTag/${local.blocked_tag_key}"
      values   = [local.blocked_tag_value]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.detector.arn]
    }
  }

  # Without this, whoever can write tags could simply remove the "blocked" tag.
  statement {
    sid    = "DenyUnblockingByTagChange"
    effect = "Deny"
    actions = [
      "s3:PutObjectTagging",
      "s3:PutObjectVersionTagging",
      "s3:DeleteObjectTagging",
      "s3:DeleteObjectVersionTagging",
    ]
    resources = ["${aws_s3_bucket.outbound.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:ExistingObjectTag/${local.blocked_tag_key}"
      values   = [local.blocked_tag_value]
    }

    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.detector.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "outbound" {
  bucket = aws_s3_bucket.outbound.id
  policy = data.aws_iam_policy_document.outbound.json

  depends_on = [aws_s3_bucket_public_access_block.outbound]
}

# ---------------------------------------------------------------------------------------
# Quarantine bucket: private, versioned, expiring. No event notification on purpose, so
# moving an object here can never trigger the detector again.
# ---------------------------------------------------------------------------------------

resource "aws_s3_bucket" "quarantine" {
  count = var.enable_quarantine ? 1 : 0

  bucket        = local.quarantine_bucket_name
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_public_access_block" "quarantine" {
  count = var.enable_quarantine ? 1 : 0

  bucket                  = aws_s3_bucket.quarantine[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "quarantine" {
  count = var.enable_quarantine ? 1 : 0

  bucket = aws_s3_bucket.quarantine[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "quarantine" {
  count = var.enable_quarantine ? 1 : 0

  bucket = aws_s3_bucket.quarantine[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "quarantine" {
  count = var.enable_quarantine ? 1 : 0

  bucket = aws_s3_bucket.quarantine[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "quarantine" {
  count = var.enable_quarantine ? 1 : 0

  bucket = aws_s3_bucket.quarantine[0].id

  rule {
    id     = "expire-quarantined-objects"
    status = "Enabled"

    filter {}

    expiration {
      days = var.quarantine_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.quarantine_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.quarantine]
}

# The quarantine bucket policy only carries the TLS rule, so it exists only when that rule does.
data "aws_iam_policy_document" "quarantine" {
  count = var.enable_quarantine && var.enforce_tls ? 1 : 0

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.quarantine[0].arn, "${aws_s3_bucket.quarantine[0].arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "quarantine" {
  count = var.enable_quarantine && var.enforce_tls ? 1 : 0

  bucket = aws_s3_bucket.quarantine[0].id
  policy = data.aws_iam_policy_document.quarantine[0].json

  depends_on = [aws_s3_bucket_public_access_block.quarantine]
}

# ---------------------------------------------------------------------------------------
# S3 -> Lambda event wiring for every monitored bucket.
# ---------------------------------------------------------------------------------------

resource "aws_lambda_permission" "allow_s3" {
  for_each = toset(local.monitored_bucket_names)

  statement_id   = "AllowS3-${substr(sha1(each.key), 0, 12)}"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.detector.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = "arn:${local.partition}:s3:::${each.key}"
  source_account = local.account_id
}

resource "aws_s3_bucket_notification" "monitored" {
  for_each = toset(local.monitored_bucket_names)

  bucket = each.key

  lambda_function {
    lambda_function_arn = aws_lambda_function.detector.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.allow_s3, aws_s3_bucket.outbound]
}
