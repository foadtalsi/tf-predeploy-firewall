resource "aws_iam_policy" "reader" {
  name = "reader"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::acme-reports/*"
    }]
  })
}
