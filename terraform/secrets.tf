# Fake static credential used only to exercise secret-scanning rules.
locals {
  fixture_access_key = "AKIAIOSFODNN7EXAMPLE"                     # FINDING: SEC-050 CWE-798 tf-locals-aws-access-key
  fixture_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" # FINDING: SEC-051 CWE-798 tf-locals-aws-secret-key
}

variable "db_password" {
  type    = string
  default = "Sup3rS3cret!" # FINDING: SEC-052 CWE-798 tf-variable-default-password
  # FINDING: SEC-053 CWE-532 tf-variable-not-sensitive (sensitive = true absent)
}
