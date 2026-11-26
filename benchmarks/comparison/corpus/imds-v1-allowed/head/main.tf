resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.small"

  metadata_options {
    http_tokens = "optional"
  }

  root_block_device {
    encrypted = true
  }
}
