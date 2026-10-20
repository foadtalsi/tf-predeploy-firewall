# Positives: a change to an argument that forces the resource to be replaced.
resource "aws_db_instance" "orders" {
  identifier = "orders"
  engine     = "mysql"
  username   = "orders_admin"
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs-eu-west-1"
}

resource "aws_dynamodb_table" "sessions" {
  name     = "sessions"
  hash_key = "session_id"
}

resource "aws_instance" "web" {
  ami           = "ami-0fedcba9876543210"
  instance_type = "t3.micro"
  subnet_id     = "subnet-aaaaaaaaaaaaaaaaa"
}

resource "aws_db_instance" "reporting" {
  identifier        = "reporting"
  engine            = "postgres"
  storage_encrypted = true
}

# Near misses: in-place updates, and new resources with nothing to replace.
resource "aws_db_instance" "resized" {
  identifier     = "resized"
  engine         = "postgres"
  instance_class = "db.t3.large"
}

resource "aws_s3_bucket" "tagged" {
  bucket = "acme-tagged"
  tags   = { team = "data" }
}

resource "aws_instance" "upsized" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "m5.large"
}

resource "aws_db_instance" "brand_new" {
  identifier = "brand-new"
  engine     = "postgres"
}
