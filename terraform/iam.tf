######################## LAMBDA IAM POLICY ########################
resource "aws_iam_role" "lambda_exec_role" {
  name                = "lambda-autotag"
  assume_role_policy  = data.aws_iam_policy_document.lambda_assume_role_policy.json
  managed_policy_arns = [data.aws_iam_policy.lambda_basic_execution_role_policy.arn]
  inline_policy {
    name   = "AutotagFunctionPermissions"
    policy = data.aws_iam_policy_document.lambda_inline_policy.json
  }
}

data "aws_iam_policy_document" "lambda_assume_role_policy" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

# Customer Managed Policy
data "aws_iam_policy_document" "lambda_inline_policy" {
  statement {
    sid    = "AllowTaggingOfSNSTopic"
    effect = "Allow"
    actions = ["iam:ListRoleTags", "iam:ListUserTags",
      "dynamodb:TagResource", "dynamodb:DescribeTable",
      "lambda:TagResource", "lambda:ListTags",
      "s3:GetBucketTagging", "s3:PutBucketTagging",
      "ec2:CreateTags", "ec2:DescribeNatGateways", "ec2:DescribeInternetGateways", "ec2:DescribeInstances", "ec2:DescribeVolumes",
      "rds:AddTagsToResource", "rds:DescribeDBInstances",
      "sns:TagResource", "sqs:ListQueueTags", "sqs:TagQueue",
      "es:AddTags", "kms:ListResourceTags", "kms:TagResource",
      "elasticfilesystem:TagResource", "elasticfilesystem:CreateTags", "elasticfilesystem:DescribeTags",
      "elasticloadbalancing:AddTags", "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
      "tag:getResources", "tag:getTagKeys", "tag:getTagValues", "tag:TagResources", "tag:UntagResources",
      "cloudformation:DescribeStacks", "cloudformation:ListStackResources",
      "elasticache:DescribeReplicationGroups", "elasticache:DescribeCacheClusters", "elasticache:AddTagsToResource",
    "resource-groups:*"]
    resources = ["*"]
  }
  statement {
    sid       = "AllowLambdaCreateLogGroup"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup"]
    resources = ["arn:aws:logs:${var.aws_region}:*:log-group:*"]
  }
  statement {
    sid       = "AllowLambdaCreateLogStreamsAndWriteEventLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda_log_grp.arn}:*"]
  }
}

# AWS Managed Policy
data "aws_iam_policy" "lambda_basic_execution_role_policy" {
  name = "AWSLambdaBasicExecutionRole"
}


######################## CLOUDTRAIL BUCKET POLICY ########################
data "aws_iam_policy_document" "cloudtrail_bucket_policy_doc" {
  count = var.create_trail ? 1 : 0

  statement {
    sid    = "AllowCloudTrailCheckBucketAcl"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_bucket[count.index].arn]
  }

  statement {
    sid    = "AllowCloudTrailWriteLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_bucket[count.index].arn}/AWSLogs/*"]
  }

}

