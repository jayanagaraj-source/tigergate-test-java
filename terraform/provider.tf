# Provider with static credentials inline (fake). Do not apply.
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"                     # FINDING: IAC-001 CWE-798 tf-provider-hardcoded-access-key
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" # FINDING: IAC-002 CWE-798 tf-provider-hardcoded-secret-key
}
