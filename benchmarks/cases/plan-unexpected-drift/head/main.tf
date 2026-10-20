resource "aws_db_instance" "orders" {
  identifier = "orders"
  engine     = "postgres"
}

resource "aws_db_instance" "billing" {
  identifier = "billing"
  username   = "billing_admin"
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs"
}

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
}

resource "aws_dynamodb_table" "sessions" {
  name     = "sessions"
  hash_key = "id"
}

resource "aws_db_instance" "reporting" {
  identifier = "reporting"
  engine     = "mysql"
}

resource "aws_db_instance" "resized" {
  identifier     = "resized"
  instance_class = "db.t3.large"
}
