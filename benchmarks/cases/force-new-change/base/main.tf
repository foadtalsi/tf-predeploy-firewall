resource "aws_db_instance" "orders" {
  identifier = "orders"
  engine     = "postgres"
  username   = "orders_admin"
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs-eu"
}

resource "aws_dynamodb_table" "sessions" {
  name     = "sessions"
  hash_key = "id"
}

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  subnet_id     = "subnet-aaaaaaaaaaaaaaaaa"
}

resource "aws_db_instance" "reporting" {
  identifier        = "reporting"
  engine            = "postgres"
  storage_encrypted = false
}

resource "aws_db_instance" "resized" {
  identifier     = "resized"
  engine         = "postgres"
  instance_class = "db.t3.micro"
}

resource "aws_s3_bucket" "tagged" {
  bucket = "acme-tagged"
  tags   = { team = "platform" }
}

resource "aws_instance" "upsized" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
}
