#DevSecOps CRITICAL (Checkov IaC)
#Purpose: Validate that insecure IaC blocks the merge request

resource "aws_security_group" "bad_sg" {
  name        = "bad_sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
