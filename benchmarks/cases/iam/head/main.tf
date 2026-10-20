# Positives: policies granting every action, or granting to every principal unconditionally.
resource "aws_iam_policy" "admin" {
  name = "admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "everything_on_bucket" {
  name = "everything"
  role = "app"
  policy = <<-JSON
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": ["*"],
        "Resource": "arn:aws:s3:::acme-data/*"
      }]
    }
  JSON
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket = "acme-site"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::acme-site/*"
    }]
  })
}

resource "aws_iam_role" "anyone_can_assume" {
  name = "anyone"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_sqs_queue_policy" "open_queue" {
  queue_url = "https://sqs.eu-west-1.amazonaws.com/123456789012/orders"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "sqs:SendMessage"
      Resource  = "arn:aws:sqs:eu-west-1:123456789012:orders"
    }]
  })
}

data "aws_iam_policy_document" "admin_actions" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "all_actions_on_table" {
  statement {
    actions   = ["*"]
    resources = ["arn:aws:dynamodb:eu-west-1:123456789012:table/orders"]
  }
}

data "aws_iam_policy_document" "all_actions_second_statement" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::acme-data/*"]
  }

  statement {
    actions   = ["*"]
    resources = ["arn:aws:s3:::acme-data"]
  }
}

data "aws_iam_policy_document" "all_actions_kms" {
  statement {
    actions   = ["*"]
    resources = ["arn:aws:kms:eu-west-1:123456789012:key/1234abcd"]
  }
}

data "aws_iam_policy_document" "all_actions_queue" {
  statement {
    actions   = ["*"]
    resources = ["arn:aws:sqs:eu-west-1:123456789012:orders"]
  }
}

data "aws_iam_policy_document" "public_bucket" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::acme-site/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "any_account" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "public_topic" {
  statement {
    actions   = ["sns:Publish"]
    resources = ["arn:aws:sns:eu-west-1:123456789012:alerts"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "public_queue" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = ["arn:aws:sqs:eu-west-1:123456789012:orders"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "public_key" {
  statement {
    actions   = ["kms:Decrypt"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

# Near misses.
resource "aws_iam_policy" "read_only_everywhere" {
  name = "read-only"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = "*"
    }]
  })
}

resource "aws_s3_bucket_policy" "organization_only" {
  bucket = "acme-shared"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::acme-shared/*"
      Condition = { StringEquals = { "aws:PrincipalOrgID" = "o-example" } }
    }]
  })
}

resource "aws_iam_role" "ec2_can_assume" {
  name = "ec2"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "service_wildcard" {
  name = "s3-admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:*"
      Resource = "arn:aws:s3:::acme-data/*"
    }]
  })
}

data "aws_iam_policy_document" "scoped_actions" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["arn:aws:s3:::acme-data/*"]
  }
}

data "aws_iam_policy_document" "service_wildcard" {
  statement {
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::acme-data/*"]
  }
}

data "aws_iam_policy_document" "actions_from_variable" {
  statement {
    actions   = var.allowed_actions
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "named_account" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:root"]
    }
  }
}

data "aws_iam_policy_document" "service_principal" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "principal_from_variable" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = var.trusted_accounts
    }
  }
}
