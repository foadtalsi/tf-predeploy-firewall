locals {
  fn        = jsonencode({ Statement = [{ Action = "*" }] })
  nested_fn = merge({ a = 1 }, { b = 2 })
  spread    = max(1, 2, 3)
  expand    = min([1, 2, 3]...)
  ns_fn     = provider::aws::arn_parse("arn:x")
  for_tuple = [for x in [1, 2, 3] : x * 2]
  for_obj   = { for k, v in { a = 1 } : k => v }
  for_if    = [for x in [1, 2, 3] : x if x > 1]
  for_group = { for k, v in {} : k => v... }
  splat     = aws_instance.web[*].id
  splat_dot = aws_instance.web.*.id
  ref_res   = aws_s3_bucket.no_lifecycle.arn
}
