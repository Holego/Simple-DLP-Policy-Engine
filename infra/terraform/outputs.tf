output "outbound_bucket" {
  description = "Upload files here to have them inspected."
  value       = aws_s3_bucket.outbound.id
}

output "quarantine_bucket" {
  description = "Receives offending objects (null when quarantine is disabled)."
  value       = var.enable_quarantine ? aws_s3_bucket.quarantine[0].id : null
}

output "incident_table" {
  description = "DynamoDB incident journal."
  value       = aws_dynamodb_table.incidents.name
}

output "alert_topic_arn" {
  description = "SNS topic that receives alerts."
  value       = aws_sns_topic.alerts.arn
}

output "detector_function" {
  description = "Name of the Lambda function."
  value       = aws_lambda_function.detector.function_name
}

output "dead_letter_queue_url" {
  description = "Events the detector failed to process end up here."
  value       = aws_sqs_queue.dead_letter.url
}

output "incident_reader_policy_arn" {
  description = "Managed policy that allows querying the incident journal."
  value       = aws_iam_policy.incident_reader.arn
}

output "query_incidents_command" {
  description = "Example command that lists recent high severity incidents."
  value       = "python cli.py incident-log query --backend dynamodb --table ${aws_dynamodb_table.incidents.name} --severity high --last 7d"
}
