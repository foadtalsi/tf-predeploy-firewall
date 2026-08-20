resource "aws_db_instance" "primary" {
  identifier     = "prod-db"
  engine         = "mysql"
  username       = "admin"
  instance_class = "db.t3.medium"
}
