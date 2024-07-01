import boto3
import json
import time
import argparse
from colorama import Back, Style

#https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/
#https://github.com/WeAreCloudar/s3-account-search/blob/main/s3_account_search/cli.py
#https://tracebit.com/blog/2024/02/finding-aws-account-id-of-any-s3-bucket/#void
#https://hackingthe.cloud/aws/enumeration/account_id_from_s3_bucket/

#https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html
#https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html

#Applicable policy elements that allow wildcards: - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
#aws:userid - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
#s3:ResourceAccount - https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html


#TODO: Can this be applied to s3 bucket policies or resource policies when trying to list/copy bucket contents cross account?


#Basic Get-Going Setup: This version uses an IAM user with customer managed policies or inline policies attached to the IAM user you're using
#1. Create a new customer managed policy or an inline IAM policy (in the console, cli or boto) with the following below
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
# 						"0*" 
# 					]
# 				}
# 			}
# 		}
# 	]
# }

#2. Create a new IAM user and attach the custom managed policy or attach via inline made in step one and the AWS managed policy named IAMFullAccess

#3. This script can be customized in hundreds of different ways to fit your scenario





parser = argparse.ArgumentParser(description = "Enumerate IAM resources in target AWS accounts by using a role policy in your AWS account.")
parser.add_argument("-b", "--bucketnames", help="Bucket names to enumerate AWS account IDs from.", required=True, action="append")
parser.add_argument("-p", "--policyname", help="The name of the inline policy being used for the user.", required=True)
parser.add_argument("-v", "--verbose", action="store_true", help="Give verbose output including invalid resources.", required=False)
parser.add_argument("-k", "--keyid", help="AWS Key ID", required=True)
parser.add_argument("-s", "--accesskey", help="AWS Access Key", required=True)


#Inline Policy Version

def FindID(BucketNames, PolicyName, IAMUser):
    accountId = []
    policy = iam.get_user_policy(UserName=IAMUser, PolicyName=PolicyName)['PolicyDocument']

    # Reset the inline policy before starting
    policy["Statement"][0]["Condition"]["StringLike"]["s3:ResourceAccount"][0] = "0*"
    response = iam.put_user_policy(UserName=IAMUser, PolicyName=PolicyName, PolicyDocument=json.dumps(policy))

    for bucket in BucketNames:
        for _ in range(0,12,1):
            for digit in range(0,10,1):
                try:
                    policy["Statement"][0]["Condition"]["StringLike"]["s3:ResourceAccount"][0] = "{}{}*".format("".join(accountId), digit)

                    response = iam.put_user_policy(UserName=IAMUser, PolicyName=PolicyName, PolicyDocument=json.dumps(policy))

                    time.sleep(7) #This is needed for the inline policy changes to initialize otherwise a race condition is created where listing the bucket objects is done before the policy update resulting in a FP failure

                    if(response["ResponseMetadata"]["HTTPStatusCode"] == 200):
                        s3.list_objects(Bucket=bucket) #s3.head_bucket(Bucket=bucket) also works here
                        accountId.append(str(digit))
                        print("({}/12) Bucket {} belongs to the account with ID: {}".format((_ + 1), bucket, "".join(accountId)))
                        break # Potentially make it faster by removing this and finishing the loop and checking at the beginning to see if the list accountId has 12 digits already               

                except Exception as e:
                    if args.verbose:
                        print("{}: {}".format(policy["Statement"][0]["Condition"]["StringLike"]["s3:ResourceAccount"][0], e))
                        pass
                    else:
                        pass
            
            if len(accountId) == 0:
                print("[!]: The bucket does not look like it is publicly accessible or accessible from the IAM user you are using. Please try another IAM user or adjust permissions.")
                break
    

if __name__ == "__main__":

    args = parser.parse_args()

    #https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html
    #https://boto3.amazonaws.com/v1/documentation/api/latest/guide/session.html
    session = boto3.Session(aws_access_key_id=args.keyid, aws_secret_access_key=args.accesskey)
    
    iam = session.client("iam")
    sts = session.client("sts")
    s3 = session.client("s3")
    IAMUser = sts.get_caller_identity()["Arn"].split("/")[1]

    if args.verbose:
        userPolicies = iam.list_user_policies(UserName=IAMUser)["PolicyNames"]
        
        print("="*50)
        print("IAM Policies for User: {}\n".format(IAMUser))
        
        for policy in userPolicies:
            print("{}".format(policy))
            print("-"*50)
            print(json.dumps(iam.get_user_policy(UserName=IAMUser, PolicyName=policy)["PolicyDocument"], indent=4))
            print("\n")
            

    FindID(args.bucketnames, args.policyname, IAMUser)













# Managed Customer Policy Verison

# def FindID(BucketNames, PolicyName, IAMUser):
#     accountId = []
#     policy = iam.get_user_policy(UserName=IAMUser, PolicyName=PolicyName)['PolicyDocument']

#     for bucket in BucketNames:
#         for i in range(0,11,1):
#             for d in range(0,10,1):
#                 try:
#                     if len(accountId) == 12:
#                         break

#                     policy["Statement"][0]["Condition"]["StringLike"]["s3:ResourceAccount"][0] = "{}{}*".format("".join(accountId), d)

#                     response = iam.put_user_policy(UserName=IAMUser, PolicyName=PolicyName, PolicyDocument=json.dumps(policy))
#                     time.sleep(5)

#                     if(response["ResponseMetadata"]["HTTPStatusCode"] == 200):
#                         s3.list_objects(Bucket=bucket)
#                         accountId.append(str(d))
#                         print("Account ID for Bucket {}: {}".format(bucket, "".join(accountId)))

#                 except Exception as e:
#                     print(e)
#                     if args.verbose:
#                         print("{}: {}".format(d, e))
#                         pass
#                     else:
#                         pass
            
#             if len(accountId) <= 0:
#                 print("[!]: The bucket does not look like it is publicly accessible or accessible from the role you are using. Please try another role.")
#                 break

#     policy["Statement"][0]["Condition"]["StringLike"]["s3:ResourceAccount"][0] = "0*"
    

# if __name__ == "__main__":

#     args = parser.parse_args()

#     #https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html
#     #https://boto3.amazonaws.com/v1/documentation/api/latest/guide/session.html
#     session = boto3.Session(aws_access_key_id=args.keyid, aws_secret_access_key=args.accesskey)
    
#     iam = session.client("iam")
#     sts = session.client("sts")
#     s3 = session.client("s3")
#     IAMUser = sts.get_caller_identity()["Arn"].split("/")[1]

#     if args.verbose:
#         IAMPolicy = iam.list_policies()
        
#         for Name in IAMPolicies:
#             policy = iam.get_user_policy(UserName=IAMUser, PolicyName=Name)
#             IAMPolicies.update({policy['PolicyName']: policy['PolicyDocument']})
        
#         print("="*50)
#         print("IAM Policies for User: {}\n".format(IAMUser))

#         for IAMPolicy in IAMPolicies:
#             print(IAMPolicy)
#             print("-"*50)
#             print(json.dumps(IAMPolicies[IAMPolicy], indent=4))
#             print("\n")
            

#     FindID(args.bucketnames, args.policyname, IAMUser)

