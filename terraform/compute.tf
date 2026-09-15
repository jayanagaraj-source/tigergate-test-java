resource "aws_instance" "app" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.wide_open.id]
  associate_public_ip_address = true  # FINDING: IAC-020 CWE-284 tf-ec2-public-ip
  monitoring                  = false # FINDING: IAC-021 CWE-778 tf-ec2-detailed-monitoring-off

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional" # FINDING: IAC-022 CWE-284 tf-ec2-imdsv1-allowed
  }

  root_block_device {
    encrypted = false # FINDING: IAC-023 CWE-311 tf-ec2-root-volume-unencrypted
  }

  # FINDING: IAC-024 CWE-798 tf-ec2-secret-in-user-data
  user_data = <<-EOT
    #!/bin/bash
    export DB_PASSWORD="Sup3rS3cret!"
    export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  EOT
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false # FINDING: IAC-025 CWE-311 tf-ebs-unencrypted
}

resource "aws_launch_template" "app" {
  name          = "fixture-lt"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "optional" # FINDING: IAC-026 CWE-284 tf-launch-template-imdsv1
  }
}

resource "aws_lambda_function" "worker" {
  function_name = "fixture-worker"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "python3.7" # FINDING: IAC-027 CWE-1104 tf-lambda-deprecated-runtime
  filename      = "worker.zip"
  environment {
    variables = {
      API_KEY = "sk_live_F1xTuR3F4k3K3yAbCdEfGhIjKl" # FINDING: IAC-028 CWE-798 tf-lambda-secret-in-env
    }
  }
  # FINDING: IAC-029 CWE-778 tf-lambda-tracing-disabled (no tracing_config block)
}
