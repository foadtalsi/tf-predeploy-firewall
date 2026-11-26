resource "aws_rds_cluster" "main" {
  cluster_identifier          = "main"
  engine                      = "aurora-postgresql"
  master_username             = "appuser"
  manage_master_user_password = true
  storage_encrypted           = true

  lifecycle {
    prevent_destroy = true
  }
}
