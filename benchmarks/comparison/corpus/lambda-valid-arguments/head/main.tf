resource "aws_lambda_function" "worker" {
  function_name = "worker"
  role          = "arn:aws:iam::123456789012:role/worker"
  runtime       = "java21"
  handler       = "com.acme.Handler::handleRequest"
  filename      = "worker.zip"
  memory_size   = 1024
  timeout       = 30

  ephemeral_storage {
    size = 2048
  }

  snap_start {
    apply_on = "PublishedVersions"
  }
}
