resource "aws_iam_policy" "admin_star" {
  name = "fixture-admin-star"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*" # FINDING: IAC-070 CWE-269 tf-iam-policy-action-wildcard
      Resource = "*" # FINDING: IAC-071 CWE-269 tf-iam-policy-resource-wildcard
    }]
  })
}

resource "aws_iam_policy" "passrole" {
  name = "fixture-passrole"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "sts:AssumeRole"] # FINDING: IAC-072 CWE-269 tf-iam-privilege-escalation-passrole
      Resource = "*"
    }]
  })
}

resource "aws_iam_user" "deploy" {
  name = "fixture-deploy" # FINDING: IAC-073 CWE-269 tf-iam-user-instead-of-role
}

resource "aws_iam_user_policy_attachment" "deploy_admin" {
  user       = aws_iam_user.deploy.name # FINDING: IAC-074 CWE-269 tf-iam-policy-attached-directly-to-user
  policy_arn = aws_iam_policy.admin_star.arn
}

resource "aws_iam_access_key" "deploy" {
  user = aws_iam_user.deploy.name # FINDING: IAC-075 CWE-798 tf-iam-access-key-in-terraform-state
}

resource "aws_iam_role" "lambda" {
  name = "fixture-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "*" } # FINDING: IAC-076 CWE-284 tf-iam-assume-role-principal-wildcard
    }]
  })
}

resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 6     # FINDING: IAC-077 CWE-521 tf-iam-password-min-length
  require_lowercase_characters   = false # FINDING: IAC-078 CWE-521 tf-iam-password-no-lowercase
  require_numbers                = false # FINDING: IAC-079 CWE-521 tf-iam-password-no-numbers
  require_uppercase_characters   = false # FINDING: IAC-080 CWE-521 tf-iam-password-no-uppercase
  require_symbols                = false # FINDING: IAC-081 CWE-521 tf-iam-password-no-symbols
  allow_users_to_change_password = true
  max_password_age               = 0 # FINDING: IAC-082 CWE-521 tf-iam-password-no-expiry
  password_reuse_prevention      = 0 # FINDING: IAC-083 CWE-521 tf-iam-password-reuse-allowed
}
