resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-3a"
  size              = 200
  encrypted         = false
}
