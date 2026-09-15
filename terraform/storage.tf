resource "aws_s3_bucket" "logs" {
  bucket = "tigergate-fixture-logs"
  acl    = "public-read" # FINDING: IAC-050 CWE-284 tf-s3-public-read-acl
  # FINDING: IAC-051 CWE-311 tf-s3-no-sse (no server_side_encryption_configuration)
  # FINDING: IAC-052 CWE-693 tf-s3-versioning-disabled (no versioning block)
  # FINDING: IAC-053 CWE-778 tf-s3-access-logging-disabled (no logging block)
}

resource "aws_s3_bucket_policy" "logs_anyone" {
  bucket = aws_s3_bucket.logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*" # FINDING: IAC-054 CWE-284 tf-s3-policy-principal-wildcard
      Action    = "s3:*"
      Resource  = ["${aws_s3_bucket.logs.arn}/*"]
    }]
  })
}

resource "aws_s3_bucket" "unversioned" {
  bucket        = "tigergate-fixture-data"
  force_destroy = true # FINDING: IAC-055 CWE-693 tf-s3-force-destroy
  versioning {
    enabled    = false # FINDING: IAC-056 CWE-693 tf-s3-versioning-explicitly-off
    mfa_delete = false # FINDING: IAC-057 CWE-693 tf-s3-mfa-delete-off
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256" # FINDING: IAC-058 CWE-311 tf-s3-sse-not-kms
      }
    }
  }
}

resource "aws_ecr_repository" "app" {
  name                 = "tigergate-fixture"
  image_tag_mutability = "MUTABLE" # FINDING: IAC-059 CWE-494 tf-ecr-mutable-tags
  image_scanning_configuration {
    scan_on_push = false # FINDING: IAC-060 CWE-1104 tf-ecr-scan-on-push-off
  }
  # FINDING: IAC-061 CWE-311 tf-ecr-no-kms (encryption_configuration absent)
}

resource "aws_efs_file_system" "shared" {
  encrypted = false # FINDING: IAC-062 CWE-311 tf-efs-unencrypted
}
