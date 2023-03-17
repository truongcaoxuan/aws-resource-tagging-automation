<h2 align="center">Auto tag AWS solution deployed with Terraform</h2>

<h2 align="center">AWS Autotag Achitecture</h2>

![Solution](https://github.com/yemisprojects/aws-autotag/blob/main/images/Architecture.png)
<h4 align="center"></h4>

<h2 align="center">Technical overview</h2>

This solution uses an automated workflow to tag newly created resources. When an AWS resource is created a corresponding event is logged by AWS Cloudtrail. This event will be captured by Eventbridge and trigger a rule set to monitor selected events. The triggered rule sends the event to a Lambda function to be processed. The Lambda function identifies the name of the IAM user or role that created the resource and tags the resource with the same name and any associated tags applied to the user or role.

## Pre-requisites
- Terraform CLI (1.0+) installed
- An AWS account and user account with admin permissions
- AWS CLI (2.0+) installed

## Deployment Steps

```bash
git clone https://github.com/yemisprojects/aws-autotag.git && cd aws-autotag
terraform init
terraform plan
terraform apply --auto-approve
```

## Reference from
- [Medium blog post : How to Tag New AWS Resources Automatically and Deploy the solution with Terraform](https://aws.plainenglish.io/how-to-auto-tag-new-aws-resources-and-deploy-solution-with-terraform-de48ec644d95)
- [AWS blog post : Automatically tag new AWS resources based on identity or role](https://aws.amazon.com/blogs/mt/auto-tag-aws-resources/)
- [Stackoverflow post : How do you automate tagging using a Lambda function on AWS](https://stackoverflow.com/questions/56484540/how-do-you-automate-tagging-using-a-lambda-function-on-aws)
- [AWS blog post : Automatically tag new AWS resources based on identity or role](https://aws.amazon.com/blogs/mt/auto-tag-aws-resources/)
