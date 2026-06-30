resource "aws_db_instance" "primary" {
  identifier = "prod-db"
  engine     = "postgres"
  username   = "admin"
}
