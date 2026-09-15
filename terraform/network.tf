resource "aws_vpc" "fixture" {
  cidr_block = "10.0.0.0/16"
  # FINDING: IAC-010 CWE-778 tf-vpc-flow-logs-disabled (no aws_flow_log resource references this VPC)
}

resource "aws_security_group" "wide_open" {
  name   = "fixture-wide-open"
  vpc_id = aws_vpc.fixture.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # FINDING: IAC-011 CWE-284 tf-sg-ssh-open-to-world
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # FINDING: IAC-012 CWE-284 tf-sg-rdp-open-to-world
  }

  ingress {
    from_port        = 0
    to_port          = 65535
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"] # FINDING: IAC-013 CWE-284 tf-sg-all-ports-open-to-world
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # FINDING: IAC-014 CWE-284 tf-sg-unrestricted-egress
  }
}

resource "aws_network_acl" "permissive" {
  vpc_id = aws_vpc.fixture.id
  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0" # FINDING: IAC-015 CWE-284 tf-nacl-allow-all-ingress
    from_port  = 0
    to_port    = 0
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.fixture.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true # FINDING: IAC-016 CWE-284 tf-subnet-auto-assign-public-ip
}
