"""
This function is triggered by an Amazon EventBridge rule when a new AWS Resource is created.
It extracts the identity of the resource creator and tags each newly AWS Resource with this identity
and it's associated tags
"""
import os
import boto3
import json
import logging
from botocore.exceptions import ClientError

log_level = {
                "CRITICAL": logging.CRITICAL,
                "ERROR" : logging.ERROR,
                "WARNING" : logging.WARNING,
                "INFO" : logging.INFO,
                "DEBUG" : logging.DEBUG
            }
log = logging.getLogger(__name__)
log.setLevel(log_level[os.environ.get('LOG_LEVEL',"DEBUG")])

# ------------------------------------
# GET Tags List
# ------------------------------------
def get_iam_identity_tags(user_name=None, role_name=None):
    """
    Gets and returns a list of tags from an iam user or role
    """
    iam_client = boto3.client('iam')

    if user_name:
        response = iam_client.list_user_tags(UserName=user_name)
    elif role_name:
        response = iam_client.list_role_tags(RoleName=role_name)

    tags = response.get("Tags")
    while response.get("Marker"):
        if user_name:
            response = iam_client.list_user_tags(UserName=user_name, Marker=response.get("Marker"))
        elif role_name:
            response = iam_client.list_role_tags(RoleName=role_name, Marker=response.get("Marker"))
        tags.extend(response.get('Tags'))

    log.debug(f"Tags parsed from IAM identity: {tags}")    
    return tags

def get_resource_tag(event):
    """
    Takes in a cloudtrail event, extract IAM identity and returns a list of resource tags 
    """
    resource_tags = []
    if 'detail' in event:
        try:
            if 'userIdentity' in event['detail']:
                user_id = event['detail']['userIdentity']

                if user_id["type"] == "IAMUser" and user_id["userName"]:
                    user_name = user_id["userName"]
                    resource_tags.append( {"Owner": user_name} )
                    resource_tags.append( {"CreatedDate": event["detail"]["eventTime"]} )  
                    log.debug(f"IAM user tags parsed from Cloudtrail event: {resource_tags}")
                    #try:
                    #    tags = get_iam_identity_tags(user_name=user_name)
                    #    resource_tags.extend(tags)
                    #except ClientError as error:
                    #    log.exception(error)
                    
                elif user_id["type"] == "AssumedRole" and user_id["arn"]:
                    role_name = user_id["arn"].split("/")[-2]
                    resource_tags.append( {"CreatedByRole": role_name} )
                    resource_tags.append( {"CreatedDate": event["detail"]["eventTime"]} )  
                    log.debug(f"IAM Role tags parsed from Cloudtrail event: {resource_tags}")
                    #try:
                    #    tags = get_iam_identity_tags(role_name=role_name)
                    #    resource_tags.extend(tags)
                    #except ClientError as error:
                    #    log.exception(error)
                elif event['detail']['userIdentity']['type'] == 'Root':
                    user_name = 'root'
                    resource_tags.append( {"Owner": user_name} )
                    resource_tags.append( {"CreatedDate": event["detail"]["eventTime"]} )  
                    log.debug(f"root tags parsed from Cloudtrail event: {resource_tags}")
                    #try:
                    #    tags = get_iam_identity_tags(user_name=user_name)
                    #    resource_tags.extend(tags)
                    #except ClientError as error:
                    #    log.exception(error)
                else:
                    logging.info('Could not determine username (unknown iam userIdentity) ')
                    user_name = ''

        except Exception as e:
            logging.info('could not find username, exception: ' + str(e))
            user_name = ''  

    return resource_tags  
# ------------------------------------
# GET AWS Resource ARN List
# ------------------------------------
# Checked
def aws_ec2(event):
    arnList = []
    _account = event['account']
    _region = event['region']
    ec2ArnTemplate = 'arn:aws:ec2:@region@:@account@:instance/@instanceId@'
    volumeArnTemplate = 'arn:aws:ec2:@region@:@account@:volume/@volumeId@'
    if event['detail']['eventName'] == 'RunInstances':
        print("tagging for new EC2...")
        _instanceId = event['detail']['responseElements']['instancesSet']['items'][0]['instanceId']
        arnList.append(ec2ArnTemplate.replace('@region@', _region).replace('@account@', _account).replace('@instanceId@', _instanceId))

        ec2_resource = boto3.resource('ec2')
        _instance = ec2_resource.Instance(_instanceId)
        for volume in _instance.volumes.all():
            arnList.append(volumeArnTemplate.replace('@region@', _region).replace('@account@', _account).replace('@volumeId@', volume.id))

    elif event['detail']['eventName'] == 'CreateVolume':
        print("tagging for new EBS...")
        _volumeId = event['detail']['responseElements']['volumeId']
        arnList.append(volumeArnTemplate.replace('@region@', _region).replace('@account@', _account).replace('@volumeId@', _volumeId))
        
    elif event['detail']['eventName'] == 'CreateInternetGateway':
        print("tagging for new IGW...")
        
    elif event['detail']['eventName'] == 'CreateNatGateway':
        print("tagging for new Nat Gateway...")
        
    elif event['detail']['eventName'] == 'AllocateAddress':
        print("tagging for new EIP...")
        arnList.append(event['detail']['responseElements']['allocationId'])
        
    elif event['detail']['eventName'] == 'CreateVpcEndpoint':
        print("tagging for new VPC Endpoint...")
        
    elif event['detail']['eventName'] == 'CreateTransitGateway':
        print("tagging for new Transit Gateway...")

    return arnList
    
def aws_elasticloadbalancing(event):
    arnList = []
    if event['detail']['eventName'] == 'CreateLoadBalancer':
        print("tagging for new LoadBalancer...")
        lbs = event['detail']['responseElements']
        for lb in lbs['loadBalancers']:
            arnList.append(lb['loadBalancerArn'])
        return arnList

def aws_rds(event):
    arnList = []
    if event['detail']['eventName'] == 'CreateDBInstance':
        print("tagging for new RDS...")
        #db_instance_id = event['detail']['requestParameters']['dBInstanceIdentifier']
        #waiter = boto3.client('rds').get_waiter('db_instance_available')
        #waiter.wait(
        #    DBInstanceIdentifier = db_instance_id
        #)
        arnList.append(event['detail']['responseElements']['dBInstanceArn'])
        return arnList

# Checked
def aws_s3(event):
    arnList = []
    if event['detail']['eventName'] == 'CreateBucket':
        print("tagging for new S3...")
        _bkcuetName = event['detail']['requestParameters']['bucketName']
        arnList.append('arn:aws:s3:::' + _bkcuetName)
        return arnList

# Checked        
def aws_lambda(event):
    arnList = []
    _account = event['account']
    _region = event['region']
    lambdaArnTemplate = 'arn:aws:lambda:@region@:@account@:function:@functionName@'
 
    #_exist1 = event['detail']['responseElements']
    _exist2 = event['detail']['eventName'] == 'CreateFunction20150331'
    #if  _exist1!= None and _exist2:
    if  _exist2:
        #_function_name = event['detail']['responseElements']['functionName']
        _function_name = event['detail']['requestParameters']['functionName']
        print('Functin name is :', _function_name)
        
        #arnList.append(event['detail']['responseElements']['functionArn'])
        arnList.append(lambdaArnTemplate.replace('@region@', _region).replace('@account@', _account).replace('@functionName@', _function_name))
        return arnList

def aws_dynamodb(event):
    arnList = []
    if event['detail']['eventName'] == 'CreateTable':
        table_name = event['detail']['responseElements']['tableDescription']['tableName']
        waiter = boto3.client('dynamodb').get_waiter('table_exists')
        waiter.wait(
            TableName=table_name,
            WaiterConfig={
                'Delay': 123,
                'MaxAttempts': 123
            }
        )
        arnList.append(event['detail']['responseElements']['tableDescription']['tableArn'])
        return arnList

# Checked    
def aws_kms(event):
    arnList = []
    if event['detail']['eventName'] == 'CreateKey':
        arnList.append(event['detail']['responseElements']['keyMetadata']['arn'])
        return arnList

# Checked
def aws_sns(event):
    arnList = []
    _account = event['account']
    _region = event['region']
    snsArnTemplate = 'arn:aws:sns:@region@:@account@:@topicName@'
    if event['detail']['eventName'] == 'CreateTopic':
        print("tagging for new SNS...")
        _topicName = event['detail']['requestParameters']['name']
        arnList.append(snsArnTemplate.replace('@region@', _region).replace('@account@', _account).replace('@topicName@', _topicName))
        return arnList
        
# Checked
def aws_sqs(event):
    arnList = []
    _account = event['account']
    _region = event['region']
    sqsArnTemplate = 'arn:aws:sqs:@region@:@account@:@queueName@'
    if event['detail']['eventName'] == 'CreateQueue':
        print("tagging for new SQS...")
        _queueName = event['detail']['requestParameters']['queueName']
        arnList.append(sqsArnTemplate.replace('@region@', _region).replace('@account@', _account).replace('@queueName@', _queueName))
        return arnList

# Checked    
def aws_elasticfilesystem(event):
    arnList = []
    _account = event['account']
    _region = event['region']
    efsArnTemplate = 'arn:aws:elasticfilesystem:@region@:@account@:file-system/@fileSystemId@'
    if event['detail']['eventName'] == 'CreateMountTarget':
        print("tagging for new efs...")
        _efsId = event['detail']['responseElements']['fileSystemId']
        arnList.append(efsArnTemplate.replace('@region@', _region).replace('@account@', _account).replace('@fileSystemId@', _efsId))
        return arnList
        
def aws_es(event):
    arnList = []
    if event['detail']['eventName'] == 'CreateDomain':
        print("tagging for new open search...")
        arnList.append(event['detail']['responseElements']['domainStatus']['aRN'])
        return arnList

def aws_elasticache(event):
    arnList = []
    _account = event['account']
    _region = event['region']
    ecArnTemplate = 'arn:aws:elasticache:@region@:@account@:cluster:@ecId@'

    if event['detail']['eventName'] == 'CreateReplicationGroup' or event['detail']['eventName'] == 'ModifyReplicationGroupShardConfiguration':
        print("tagging for new ElastiCache cluster...")
        _replicationGroupId = event['detail']['requestParameters']['replicationGroupId']
        waiter = boto3.client('elasticache').get_waiter('replication_group_available')
        waiter.wait(
            ReplicationGroupId = _replicationGroupId,
            WaiterConfig={
                'Delay': 123,
                'MaxAttempts': 123
            }
        )
        _clusters = event['detail']['responseElements']['memberClusters']
        for _ec in _clusters:
            arnList.append(ecArnTemplate.replace('@region@', _region).replace('@account@', _account).replace('@ecId@', _ec))

    elif event['detail']['eventName'] == 'CreateCacheCluster':
        print("tagging for new ElastiCache node...")
        _cacheClusterId = event['detail']['responseElements']['cacheClusterId']
        waiter = boto3.client('elasticache').get_waiter('cache_cluster_available')
        waiter.wait(
            CacheClusterId = _cacheClusterId,
            WaiterConfig={
                'Delay': 123,
                'MaxAttempts': 123
            }
        )
        arnList.append(event['detail']['responseElements']['aRN'])

    return arnList

# ------------------------------------
# LAMBDA HANDLER
# ------------------------------------

def lambda_handler(event, context):
    """
    If Resource ARN List is created successfully, get the resource tags 
    from the event and append them to the newly AWS Resource
    """
    log.info(json.dumps(event))  
    print("input event is: ")
    print(event)
    print("new source is " + event['source'])

    # Get resource ARN
    _method = event['source'].replace('.', "_")
    resARNs = globals()[_method](event)
    print("resource arn is: ")
    print(resARNs)

    # Env Variable's Tags
    lambda_tags =  json.loads(os.environ['lambda_auto_tags'])
    print("lambda_tags is: ")
    print(lambda_tags)

    # Resource's Tags
    res_tags = get_resource_tag(event)
    print("res_tags is: ")
    print(res_tags)

    # Combine Variable'Tags and Resource's Tags
    combine_tags = dict(lambda_tags)
    for t in res_tags:
        print(t)
        combine_tags.update(t)
    print("combine_tags is: ")
    print(combine_tags)

    if res_tags:
        log.info(f"Resource tag to be appended\n{combine_tags}")
        try:
            boto3.client('resourcegroupstaggingapi').tag_resources(
                ResourceARNList=resARNs,
                Tags=combine_tags
            )
            log.info(f'Successfully tagged Resource: {resARNs}') 
            return {
                'statusCode': 200,
                'body': json.dumps('Finished map tagging with ' + event['source'])
            }
        except ClientError as error:
            log.exception(error) 