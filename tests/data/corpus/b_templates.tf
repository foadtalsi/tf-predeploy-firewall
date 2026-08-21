locals {
  esc      = "tab\there\nnewline \"quoted\" back\\slash"
  uni      = "éè \U0001F512"
  dollar   = "literal $${not} and %%{neither}"
  multi    = "a${1}b${2}c"
  nested_i = "${ "inner ${ "deepest" }" }"
  heredoc  = <<EOT
plain line
  indented kept
EOT
  dedented = <<-EOT
      first
        second
      third
    EOT
  hd_empty = <<-EOT
    EOT
  json_hd = <<-JSON
    {
      "Statement": [{"Action": "*", "Resource": "*"}]
    }
    JSON
}
