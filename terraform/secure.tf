# NEGATIVE CONTROL. Everything in this file is configured correctly
# (AWS provider 3.x inline-block style, matching versions.tf).
# A scanner that reports anything here is producing a false positive.
# SAFE: CTRL-020 tf-hardened-s3-bucket

resource "aws_kms_key" "secure" {
  description             = "hardened fixture key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_s3_bucket" "secure" {
  bucket = "tigergate-fixture-secure"
  acl    = "private"

  versioning {
    enabled    = true
    mfa_delete = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.secure.arn
      }
    }
  }

  logging {
    target_bucket = "tigergate-fixture-secure-access-logs"
    target_prefix = "access-logs/"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "secure" {
  name        = "fixture-secure"
  description = "HTTPS only, corporate range only"
  vpc_id      = aws_vpc.fixture.id

  ingress {
    description = "HTTPS from corporate range only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }

  egress {
    description = "HTTPS to VPC endpoints only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
