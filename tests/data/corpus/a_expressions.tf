locals {
  n         = 42
  f         = 3.14
  neg       = -17
  sci       = 1.5e3
  t         = true
  s         = "plain"
  interp    = "a-${local.s}-b"
  wrap      = "${local.n}"
  concat    = "x" + "y"
  arith     = 2 + 3 * 4 - 1
  paren     = (2 + 3) * 4
  cmp       = 5 > 3
  logic     = true && false || true
  notted    = !false
  cond      = local.n > 10 ? "big" : "small"
  nested_c  = local.t ? (local.n > 1 ? "a" : "b") : "c"
  tuple     = [1, "two", true, null]
  nested    = [[1, 2], [3]]
  obj       = { key = "v", other = 2 }
  obj_colon = { "quoted" : "v", bare : 1 }
  obj_multi = {
    a = 1
    b = 2
  }
  deep      = { outer = { inner = { leaf = "found" } } }
  idx_t     = local.tuple[0]
  idx_o     = local.obj["key"]
  legacy    = local.tuple.0
  attr      = local.deep.outer.inner.leaf
  trailing  = [1, 2, 3,]
  empty_l   = []
  empty_o   = {}
  empty_s   = ""
}
