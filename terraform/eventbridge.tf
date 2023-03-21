############ EVENTBRIDGE RULE ############
resource "aws_cloudwatch_event_rule" "tag_event_rule" {
  name          = "tag-event-rule"
  description   = "Triggers Lambda when new AWS Resource are created"
  is_enabled    = true
  event_pattern = <<EOF
    {
    "detail-type": ["AWS API Call via CloudTrail"],
    "source" : ["aws.ec2", "aws.elasticloadbalancing", "aws.rds", "aws.lambda", "aws.s3", "aws.dynamodb", "aws.elasticfilesystem", "aws.es", "aws.sqs", "aws.sns", "aws.kms", "aws.elasticache"],
    "detail": {
        "eventSource": ["ec2.amazonaws.com", "elasticloadbalancing.amazonaws.com", "s3.amazonaws.com", "rds.amazonaws.com", "lambda.amazonaws.com", "dynamodb.amazonaws.com", "elasticfilesystem.amazonaws.com", "es.amazonaws.com", "sqs.amazonaws.com", "sns.amazonaws.com", "kms.amazonaws.com", "elasticache.amazonaws.com"],
        "eventName": ["RunInstances", "CreateFunction20150331", "CreateBucket", "CreateDBInstance", "CreateTable", "CreateVolume", "CreateLoadBalancer", "CreateMountTarget", "CreateDomain", "CreateQueue", "CreateTopic", "CreateKey", "CreateReplicationGroup", "CreateCacheCluster", "ModifyReplicationGroupShardConfiguration"]
    }
    }
  EOF
}

############ EVENTBRIDGE TARGET ############
resource "aws_cloudwatch_event_target" "lambda" {
  depends_on = [aws_lambda_function.autotag]
  rule       = aws_cloudwatch_event_rule.tag_event_rule.name
  target_id  = "SendToLambda"
  arn        = aws_lambda_function.autotag.arn
}

resource "aws_lambda_permission" "event_brige_rule" {
  depends_on    = [aws_lambda_function.autotag]
  statement_id  = "AllowExecutionFromEventBridgeRule"
  action        = "lambda:InvokeFunction"
  function_name = var.autotag_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.tag_event_rule.arn
}

