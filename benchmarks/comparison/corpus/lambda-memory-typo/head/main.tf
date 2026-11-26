resource "aws_lambda_function" "worker" {
  function_name = "worker"
  role          = "arn:aws:iam::123456789012:role/worker"
  runtime       = "python3.12"
  handler       = "main.handler"
  filename      = "worker.zip"
  memory        = 512
  timeout       = 30
}
