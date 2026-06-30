resource "aws_instance" "web" {
  ami               = "ami-0123456789abcdef0"
  instance_type     = "t3.micro"
  enable_quantum_io = true
}
