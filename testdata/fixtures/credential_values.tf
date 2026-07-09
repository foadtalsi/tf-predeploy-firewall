resource "aws_instance" "leaky" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  # An AWS access key embedded in an arbitrary field
  user_data = "AKIAIOSFODNN7EXAMPLEKEY"
}

resource "aws_lambda_function" "with_jwt" {
  function_name = "my-func"
  role          = "arn:aws:iam::123456789012:role/lambda"
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  # JWT token hardcoded
  description = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
}
