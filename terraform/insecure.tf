# Deliberately insecure IaC fixture for scanner validation. Do not apply.
resource "aws_s3_bucket" "public_fixture" {
  bucket = "tigergate-test-java-public-fixture"
}

resource "aws_s3_bucket_public_access_block" "public_fixture" {
  bucket                  = aws_s3_bucket.public_fixture.id
  block_public_acls       = false # FINDING: IAC-003 CWE-284 tf-s3-block-public-acls-off
  block_public_policy     = false # FINDING: IAC-004 CWE-284 tf-s3-block-public-policy-off
  ignore_public_acls      = false # FINDING: IAC-005 CWE-284 tf-s3-ignore-public-acls-off
  restrict_public_buckets = false # FINDING: IAC-006 CWE-284 tf-s3-restrict-public-buckets-off
}
