resource "aws_cloudwatch_log_group" "detector" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
}

# Failed asynchronous invocations (after Lambda's own retries) land here instead of
# disappearing: an unscanned upload is a blind spot and must stay visible.
resource "aws_sqs_queue" "dead_letter" {
  name                      = "${local.prefix}-detector-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_lambda_function" "detector" {
  function_name = local.function_name
  description   = "Scans new S3 objects for sensitive data and applies DLP policies"
  role          = aws_iam_role.detector.arn

  runtime       = "python3.12"
  architectures = ["x86_64"]
  handler       = "handler.lambda_handler"
  memory_size   = var.lambda_memory_mb
  timeout       = var.lambda_timeout_seconds

  filename         = var.lambda_package_path
  source_code_hash = filebase64sha256(var.lambda_package_path)

  dead_letter_config {
    target_arn = aws_sqs_queue.dead_letter.arn
  }

  environment {
    variables = merge(
      {
        DLP_TABLE_NAME     = aws_dynamodb_table.incidents.name
        DLP_SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
        DLP_POLICY_PATH    = "policies.yaml"
        DLP_MAX_SCAN_BYTES = tostring(var.max_scan_bytes)
        DLP_RETENTION_DAYS = tostring(var.incident_retention_days)
        LOG_LEVEL          = "INFO"
      },
      var.enable_quarantine ? { DLP_QUARANTINE_BUCKET = local.quarantine_bucket_name } : {},
      var.webhook_url == "" ? {} : { DLP_WEBHOOK_URL = var.webhook_url },
    )
  }

  depends_on = [
    aws_cloudwatch_log_group.detector,
    aws_iam_role_policy.detector,
  ]
}
