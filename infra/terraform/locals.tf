data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  prefix     = "${var.name_prefix}-${var.environment}"

  function_name          = "${local.prefix}-detector"
  outbound_bucket_name   = "${local.prefix}-outbound-${local.account_id}"
  quarantine_bucket_name = "${local.prefix}-quarantine-${local.account_id}"

  # Every bucket whose uploads are inspected, and the ARNs the detector may touch.
  monitored_bucket_names = concat([local.outbound_bucket_name], var.additional_monitored_buckets)
  monitored_bucket_arns  = [for name in local.monitored_bucket_names : "arn:${local.partition}:s3:::${name}"]
  monitored_object_arns  = [for arn in local.monitored_bucket_arns : "${arn}/*"]

  quarantine_bucket_arn  = "arn:${local.partition}:s3:::${local.quarantine_bucket_name}"
  quarantine_object_arns = var.enable_quarantine ? ["${local.quarantine_bucket_arn}/*"] : []

  # Resources the detector is allowed to use in S3; everything else is explicitly denied.
  s3_allowed_arns = concat(
    local.monitored_bucket_arns,
    local.monitored_object_arns,
    var.enable_quarantine ? [local.quarantine_bucket_arn] : [],
    local.quarantine_object_arns,
  )

  # Tag the detector sets on objects it blocks; the outbound bucket policy keys on it.
  blocked_tag_key   = "dlp-status"
  blocked_tag_value = "blocked"
}
