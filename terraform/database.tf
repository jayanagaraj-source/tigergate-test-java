resource "aws_db_instance" "app" {
  identifier                          = "fixture-db"
  engine                              = "postgres"
  engine_version                      = "11.5" # FINDING: IAC-030 CWE-1104 tf-rds-eol-engine-version
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "app_user"
  password                            = "Sup3rS3cret!" # FINDING: IAC-031 CWE-798 tf-rds-hardcoded-password
  publicly_accessible                 = true           # FINDING: IAC-032 CWE-284 tf-rds-publicly-accessible
  storage_encrypted                   = false          # FINDING: IAC-033 CWE-311 tf-rds-storage-unencrypted
  backup_retention_period             = 0              # FINDING: IAC-034 CWE-693 tf-rds-backups-disabled
  deletion_protection                 = false          # FINDING: IAC-035 CWE-693 tf-rds-deletion-protection-off
  skip_final_snapshot                 = true
  multi_az                            = false
  iam_database_authentication_enabled = false # FINDING: IAC-036 CWE-287 tf-rds-iam-auth-disabled
  auto_minor_version_upgrade          = false # FINDING: IAC-037 CWE-1104 tf-rds-auto-minor-upgrade-off
  # FINDING: IAC-038 CWE-778 tf-rds-no-log-exports (enabled_cloudwatch_logs_exports absent)
}

resource "aws_dynamodb_table" "sessions" {
  name         = "fixture-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  point_in_time_recovery {
    enabled = false # FINDING: IAC-039 CWE-693 tf-dynamodb-pitr-disabled
  }
  # FINDING: IAC-040 CWE-311 tf-dynamodb-no-cmk-encryption (server_side_encryption absent)
}

resource "aws_elasticache_cluster" "cache" {
  cluster_id      = "fixture-cache"
  engine          = "redis"
  node_type       = "cache.t3.micro"
  num_cache_nodes = 1
  # FINDING: IAC-041 CWE-311 tf-elasticache-no-encryption (transit/at-rest encryption unavailable on aws_elasticache_cluster; should use replication_group)
}
