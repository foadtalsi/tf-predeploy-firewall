resource "aws_efs_file_system" "shared" {
  creation_token = "shared-data"
  encrypted      = true
}
