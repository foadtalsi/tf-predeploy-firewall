resource "aws_iam_role" "deployer" {
  name = "deployer"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "*" }
    }]
  })
}
