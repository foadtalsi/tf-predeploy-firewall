resource "aws_db_instance" "primary" {
  identifier = "prod-db"
  engine     = "mysql"
  username   = "admin"
}
