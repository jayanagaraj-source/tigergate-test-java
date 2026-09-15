resource "aws_cloudtrail" "audit" {
  name                          = "fixture-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  enable_log_file_validation    = false # FINDING: IAC-090 CWE-778 tf-cloudtrail-log-validation-off
  is_multi_region_trail         = false # FINDING: IAC-091 CWE-778 tf-cloudtrail-single-region
  include_global_service_events = false # FINDING: IAC-092 CWE-778 tf-cloudtrail-no-global-events
  # FINDING: IAC-093 CWE-311 tf-cloudtrail-no-kms (kms_key_id absent)
  # FINDING: IAC-094 CWE-778 tf-cloudtrail-no-cloudwatch (cloud_watch_logs_group_arn absent)
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/fixture/app"
  retention_in_days = 0 # FINDING: IAC-095 CWE-778 tf-cloudwatch-no-retention
  # FINDING: IAC-096 CWE-311 tf-cloudwatch-no-kms (kms_key_id absent)
}

resource "aws_kms_key" "app" {
  description         = "fixture key"
  enable_key_rotation = false # FINDING: IAC-100 CWE-320 tf-kms-rotation-disabled
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" } # FINDING: IAC-101 CWE-284 tf-kms-key-policy-wildcard-principal
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_sns_topic" "alerts" {
  name = "fixture-alerts"
  # FINDING: IAC-102 CWE-311 tf-sns-unencrypted (kms_master_key_id absent)
}

resource "aws_sqs_queue" "jobs" {
  name = "fixture-jobs"
  # FINDING: IAC-103 CWE-311 tf-sqs-unencrypted (kms_master_key_id absent)
}

resource "aws_sqs_queue_policy" "jobs_anyone" {
  queue_url = aws_sqs_queue.jobs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*" # FINDING: IAC-104 CWE-284 tf-sqs-policy-wildcard-principal
      Action    = "sqs:*"
      Resource  = aws_sqs_queue.jobs.arn
    }]
  })
}
