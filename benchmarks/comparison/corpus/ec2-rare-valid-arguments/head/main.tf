resource "aws_instance" "batch" {
  ami         = "ami-0c55b159cbfafe1f0"
  hibernation = true

  launch_template {
    id      = "lt-0abc1234"
    version = "$Latest"
  }

  cpu_options {
    core_count       = 2
    threads_per_core = 1
  }

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }
}
