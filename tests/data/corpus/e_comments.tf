# leading hash comment
// leading slash comment
/* block
   comment */
resource "aws_s3_bucket" "commented" { # trailing on header
  bucket = "value" # trailing on attribute
  /* inline */ acl = "private"
  tags = {
    # comment inside object
    Name = "x" // trailing inside object
  }
}
