resource "aws_instance" "web" {
  ami = "ami-0abcdef1234567890"
  tags = { Name = "web" 
}
