resource "aws_iam_role_policy" "hard" {
  name = "policy-${var.env}-${local.suffix}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })

  inline = <<-EOT
      {
        "Principal": "*",
        "Arn": "${aws_s3_bucket.data.arn}"
      }
    EOT

  raw = <<EOF
no dedent ${here}
EOF

  nested   = "${join(",", ["${var.a}", "b"])}"
  escaped  = "literal $${not_interp} and %%{nope} \"quoted\" é"
  numbers  = [1, 2.5, 1e3, 0.1]
  cond     = var.x ? "yes" : "no"
  idx      = local.list[0].attr
  splat    = aws_instance.web[*].id
  op       = 1 + 2 * 3 - -4
}
