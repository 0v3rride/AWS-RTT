import boto3
import json
import random
import argparse
from colorama import Back, Style

#https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/
#https://github.com/WeAreCloudar/s3-account-search/blob/main/s3_account_search/cli.py
#https://tracebit.com/blog/2024/02/finding-aws-account-id-of-any-s3-bucket/#void
#https://hackingthe.cloud/aws/enumeration/account_id_from_s3_bucket/

#Applicable policy elements that allow wildcards: - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
#aws:userid - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
#s3:ResourceAccount - https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html


#TODO: Can this be applied to s3 bucket policies or resource policies when trying to list/copy bucket contents cross account?
#ALTERNATIVE

#TESTED: The much simplier was of doing this is creating a new user and attaching the following inline IAM policy as the only policy to the new user (tester)
# {
# 	"Version": "2012-10-17",
# 	"Statement": [
# 		{
# 			"Sid": "AllowResourceAccount",
# 			"Effect": "Allow",
# 			"Action": "s3:*",
# 			"Resource": "*",
# 			"Condition": {
# 				"StringLike": {
# 					"s3:ResourceAccount": [
# 						"9*" ### "{}{}*".format("".join(accountId), d)
# 					]
# 				}
# 			}
# 		}
# 	]
# }



#Pre-requisite: apply this to the role you're using as an inline IAM policy in the console or via cli/boto3
# {
# 	"Version": "2012-10-17",
# 	"Statement": [
# 		{
# 			"Sid": "Statement1",
# 			"Effect": "Allow",
# 			"Action": [
# 				"s3:ListBucket",
# 				"s3:GetObject"
# 			],
# 			"Resource": "*"
# 		}
# 	]
# }


# Use these as inline policies when assuming the role which will be used for the AR SESSION; see line 68 below
# {
#         "Version": "2012-10-17",
#         "Statement": [
#             {
#                 "Sid": "AllowResourceAccount",
#                 "Effect": "Allow",
#                 "Action": "s3:*",
#                 "Resource": "*",
#                 "Condition": {
#                     "StringLike": {"s3:ResourceAccount": ["{}*"]}
#                 }
#             }
#         ]
#     }

#OR

#{ "Version": "2012-10-17", "Statement": [ { "Sid": "AllowResourceAccount", "Effect": "Allow", "Action": "s3:*", "Resource": ["arn:aws:s3:::{}/*".format(bucketName), "arn:aws:s3:::{}".format(bucketName)], "Condition": { "StringLike": {"s3:ResourceAccount": ["{}???????????".format(i)]} } } ] }


parser = argparse.ArgumentParser(description = "Enumerate IAM resources in target AWS accounts by using a role policy in your AWS account.")
parser.add_argument("-b", "--bucketnames", help="Bucket names to enumerate AWS account IDs from.", required=True, action="append")
parser.add_argument("-p", "--rolename", help="The name of the role in your AWS account to use for enumeration.", required=True)
parser.add_argument("-v", "--verbose", action="store_true", help="Give verbose output including invalid resources.", required=False)
parser.add_argument("-i", "--IAMPolicy", help="Set IAM policy for role you're using", required=False)
parser.add_argument("-k", "--keyid", help="AWS Key ID", required=True)
parser.add_argument("-s", "--accesskey", help="AWS Access Key", required=True)

def FindID(BucketName, RoleName):
    accountId = []
    roleArn = iam.get_role(RoleName=RoleName)["Role"]["Arn"]

    for bucket in BucketName:
        for i in range(0,11,1):
            for d in range(0,10,1):
                try:
                    if len(accountId) == 12:
                        break

                    #Inline policy applied to assumed role session - https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sts/client/assume_role.html
                    Policy = { "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Action": "s3:*", "Resource": "*", "Condition": { "StringLike": {"s3:ResourceAccount": ["{}{}*".format("".join(accountId), d)]} } } ] }

                    response = sts.assume_role(RoleSessionName=str(random.randint(1000,9999)), RoleArn=roleArn, Policy=json.dumps(Policy))
                    assumedRole = boto3.client('s3', aws_access_key_id=response["Credentials"]["AccessKeyId"], aws_secret_access_key=response["Credentials"]["SecretAccessKey"], aws_session_token=response["Credentials"]["SessionToken"])
                    
                    assumedRole.head_bucket(Bucket=bucket)
                    accountId.append(str(d))
                    print("Account ID for Bucket {}: {}".format(bucket, "".join(accountId)))

                except Exception as e:
                    if args.verbose:
                        print("{}: {}".format(d, e))
                        pass
                    else:
                        pass
            
            if len(accountId) <= 0:
                print("[!]: The bucket does not look like it is publicly accessible or accessible from the role you are using. Please try another role.")
                break
    

if __name__ == "__main__":

    args = parser.parse_args()

    #https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html
    #https://boto3.amazonaws.com/v1/documentation/api/latest/guide/session.html
    session = boto3.Session(aws_access_key_id=args.keyid, aws_secret_access_key=args.accesskey)
    
    iam = session.client("iam")
    sts = session.client("sts")

    if args.verbose:
        IAMPolicies = {}
        iamPolicyNames = iam.list_role_policies(RoleName=args.rolename)["PolicyNames"]
        
        for iamPolicyName in iamPolicyNames:
            policy = iam.get_role_policy(RoleName=args.rolename, PolicyName=iamPolicyName)
            IAMPolicies.update({policy['PolicyName']: policy['PolicyDocument']})
        
        print("="*50)
        print("IAM Policies for Role: {}\n".format(args.rolename))

        for IAMPolicy in IAMPolicies:
            print(IAMPolicy)
            print("-"*50)
            print(json.dumps(IAMPolicies[IAMPolicy], indent=4))
            print("\n")
            

    FindID(args.bucketnames, args.rolename)






























# import boto3
# import json
# import random
# import argparse
# from colorama import Back, Style

#https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/
#https://github.com/WeAreCloudar/s3-account-search/blob/main/s3_account_search/cli.py
#https://tracebit.com/blog/2024/02/finding-aws-account-id-of-any-s3-bucket/#void
#https://hackingthe.cloud/aws/enumeration/account_id_from_s3_bucket/

#Applicable policy elements that allow wildcards: - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
#aws:userid - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
#s3:ResourceAccount - https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html

#Can this be applied to s3 bucket policies or resource policies when trying to list/copy bucket contents cross account?


#Pre-requisite: apply this to the role you're using as an inline IAM policy in the console or via cli/boto3
# {
# 	"Version": "2012-10-17",
# 	"Statement": [
# 		{
# 			"Sid": "Statement1",
# 			"Effect": "Allow",
# 			"Action": [
# 				"s3:ListBucket",
# 				"s3:GetObject"
# 			],
# 			"Resource": "*"
# 		}
# 	]
# }


# Use these as inline policies when assuming the role which will be used for the AR SESSION; see line 68 below
# {
#         "Version": "2012-10-17",
#         "Statement": [
#             {
#                 "Sid": "AllowResourceAccount",
#                 "Effect": "Allow",
#                 "Action": "s3:*",
#                 "Resource": "*",
#                 "Condition": {
#                     "StringLike": {"s3:ResourceAccount": ["{}*"]}
#                 }
#             }
#         ]
#     }

#OR

#{ "Version": "2012-10-17", "Statement": [ { "Sid": "AllowResourceAccount", "Effect": "Allow", "Action": "s3:*", "Resource": ["arn:aws:s3:::{}/*".format(bucketName), "arn:aws:s3:::{}".format(bucketName)], "Condition": { "StringLike": {"s3:ResourceAccount": ["{}???????????".format(i)]} } } ] }


# parser = argparse.ArgumentParser(description = "Enumerate IAM resources in target AWS accounts by using a role policy in your AWS account.")
# parser.add_argument("-b", "--bucketnames", help="Bucket names to enumerate AWS account IDs from.", required=True, action="append")
# parser.add_argument("-p", "--rolename", help="The name of the role in your AWS account to use for enumeration.", required=True)
# parser.add_argument("-v", "--verbose", action="store_true", help="Give verbose output including invalid resources.", required=False)
# parser.add_argument("-i", "--setIAMPolicy", help="Set IAM policy for role you're using", required=False)
# parser.add_argument("-k", "--keyid", help="AWS Key ID", required=True)
# parser.add_argument("-s", "--accesskey", help="AWS Access Key", required=True)

# def FindID(BucketName, RoleName):
#     accountId = []
#     roleArn = iam.get_role(RoleName=RoleName)["Role"]["Arn"]

#     for bucket in BucketName:
#         for i in range(0,11,1):
#             for d in range(0,10,1):
#                 try:
#                     if len(accountId) == 12:
#                         break

#                     #Inline policy applied to assumed role session
#                     Policy = { "Version": "2012-10-17", "Statement": [ { "Sid": "Statement1", "Effect": "Allow", "Action": ["s3:*"], "Resource": "*", "Condition": { "StringLike": {"s3:ResourceAccount": ["{}{}*".format("".join(accountId), d)]} } } ] }

#                     response = sts.assume_role(RoleSessionName=str(random.randint(1000,9999)), RoleArn=roleArn, Policy=json.dumps(Policy))
#                     assumedRole = boto3.client('s3', aws_access_key_id=response["Credentials"]["AccessKeyId"], aws_secret_access_key=response["Credentials"]["SecretAccessKey"], aws_session_token=response["Credentials"]["SessionToken"])
                    
#                     assumedRole.head_bucket(Bucket=bucket)
#                     accountId.append(str(d))
#                     print("Account ID for Bucket {}: {}".format(bucket, "".join(accountId)))

#                 except Exception as e:
#                     if args.verbose:
#                         print("{}: {}".format(d, e))
#                         pass
#                     else:
#                         pass
            
#             if len(accountId) <= 0:
#                 print("[!]: The bucket does not look like it is publicly accessible or accessible from the role you are using. Please try another role.")
#                 break
    

# if __name__ == "__main__":

#     args = parser.parse_args()

#     #https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html
#     #https://boto3.amazonaws.com/v1/documentation/api/latest/guide/session.html
#     session = boto3.Session(aws_access_key_id=args.keyid, aws_secret_access_key=args.accesskey)
    
#     iam = session.client("iam")
#     sts = session.client("sts")

#     if args.verbose:
#         IAMPolicies = {}
#         iamPolicyNames = iam.list_role_policies(RoleName=args.rolename)["PolicyNames"]
        
#         for iamPolicyName in iamPolicyNames:
#             policy = iam.get_role_policy(RoleName=args.rolename, PolicyName=iamPolicyName)
#             IAMPolicies.update({policy['PolicyName']: policy['PolicyDocument']})
        
#         print("="*50)
#         print("IAM Policies for Role: {}\n".format(args.rolename))

#         for IAMPolicy in IAMPolicies:
#             print(IAMPolicy)
#             print("-"*50)
#             print(json.dumps(IAMPolicies[IAMPolicy], indent=4))
#             print("\n")
            

#     FindID(args.bucketnames, args.rolename)