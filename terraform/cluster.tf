resource "aws_eks_cluster" "app" {
  name     = "fixture-eks"
  role_arn = aws_iam_role.lambda.arn
  vpc_config {
    subnet_ids              = [aws_subnet.public.id]
    endpoint_public_access  = true # FINDING: IAC-110 CWE-284 tf-eks-public-endpoint
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"] # FINDING: IAC-111 CWE-284 tf-eks-public-cidr-world
  }
  # FINDING: IAC-112 CWE-778 tf-eks-control-plane-logging-off (enabled_cluster_log_types absent)
  # FINDING: IAC-113 CWE-311 tf-eks-secrets-not-encrypted (encryption_config absent)
}

resource "aws_lb" "app" {
  name                       = "fixture-alb"
  load_balancer_type         = "application"
  subnets                    = [aws_subnet.public.id]
  internal                   = false
  drop_invalid_header_fields = false # FINDING: IAC-114 CWE-444 tf-alb-invalid-headers-allowed
  # FINDING: IAC-115 CWE-778 tf-alb-access-logs-off (access_logs absent)
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP" # FINDING: IAC-116 CWE-319 tf-alb-plain-http-listener
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_listener" "https_weak" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08" # FINDING: IAC-117 CWE-326 tf-alb-outdated-tls-policy
  certificate_arn   = "arn:aws:acm:us-east-1:000000000000:certificate/fixture"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_target_group" "app" {
  name     = "fixture-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.fixture.id
}

resource "aws_api_gateway_rest_api" "api" {
  name = "fixture-api"
}

resource "aws_api_gateway_stage" "prod" {
  rest_api_id          = aws_api_gateway_rest_api.api.id
  deployment_id        = "fixture"
  stage_name           = "prod"
  xray_tracing_enabled = false # FINDING: IAC-118 CWE-778 tf-apigw-xray-off
  # FINDING: IAC-119 CWE-778 tf-apigw-no-access-logs (access_log_settings absent)
  # FINDING: IAC-120 CWE-693 tf-apigw-no-waf (no aws_wafv2_web_acl_association)
}
