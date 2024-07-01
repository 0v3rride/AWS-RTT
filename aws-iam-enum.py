import boto3
import argparse
import json
import io
from colorama import Back, Style
import random
import re
import threading

parser = argparse.ArgumentParser(description = "Enumerate IAM resources in target AWS accounts by using a role policy in your AWS account.")
parser.add_argument("-n", "--names", help="List containing resources (i.e. usernames, group names or role names).", required=True)
parser.add_argument("-i", "--ids", help="List containing 12 digit AWS account ids.", required=True)
parser.add_argument("-p", "--rolename", help="The name of the role in your AWS account to use for enumeration.", required=True)
parser.add_argument("-v", "--verbose", action="store_true", help="Give verbose output including invalid resources.", required=False)
parser.add_argument("-r", "--resourcetypes", action="append", help="The resource types to look for (user, role, group). Default is all three.", required=False, default=[])
parser.add_argument("-c", "--checkassumerole", action="store_true", help="If a valid role is found. Its permissions will be checked to see if the role can be assumed.", required=False)
parser.add_argument("-t", "--threads", help="Amount of threads to run on.", required=False)
parser.add_argument("-q", "--showpolicy", action="store_true", help="Show Policy in Its JSON Format.", required=False)
parser.add_argument("-k", "--keyid", help="AWS Key ID", required=True)
parser.add_argument("-s", "--accesskey", help="AWS Access Key", required=True)


#https://hackingthe.cloud/aws/enumeration/get-account-id-from-keys/
def HandleAccessKeyIdentifier(kid, sts, args):
    try:
        response = sts.get_access_key_info(AccessKeyId = kid)

        if(response["ResponseMetadata"]["HTTPStatusCode"] == 200):  
            print("{} - {}{}{}".format(Back.GREEN + "\t[+]: Account id found" + Back.RESET, Style.BRIGHT, response["Account"], Style.RESET_ALL))

    except Exception as e: 
        if(args.verbose):
            print("{} - {}".format(Back.RED + "[-]: Could not resolve key id" + Back.RESET, kid))


#https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
def HandleIAMIdentifier(uid, role, iam, args):
    role["Role"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"] = uid

    try:
        response = iam.update_assume_role_policy(RoleName="Test", PolicyDocument=json.dumps(role["Role"]["AssumeRolePolicyDocument"]))

        if(response["ResponseMetadata"]["HTTPStatusCode"] == 200):  
            role = iam.get_role(RoleName=args.rolename)
            print("{} - {}{}{}".format(Back.GREEN + "\t[+]: Unique id resolved to" + Back.RESET, Style.BRIGHT, role["Role"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"], Style.RESET_ALL))
            arn = role["Role"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"]

            if arn.split(":")[5].split("/")[0] == "role" and args.checkassumerole:
                try:
                    response = sts.assume_role(RoleArn=arn, RoleSessionName=str(random.randint(1000,9999)))

                    print(response)
                except Exception as e:
                    #print(e)
                    print("{} - {}".format(Back.YELLOW + "\t[-]: Could not assume role" + Back.RESET, arn))


    except Exception as e: 
        if(args.verbose):
            print("{} - {}".format(Back.RED + "[-]: Could not resolve identifier" + Back.RESET, uid))
    

def HandleARN(accounts, name, resourceTypes, role, iam, args):
    for account in accounts:
        for type in resourceTypes:
            try:
                #Cycle through resource types and accounts on the name  

                role["Role"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::{}:{}/{}".format(account.strip("\n"), type, name.strip("\n"))
                
                response = iam.update_assume_role_policy(RoleName="Test", PolicyDocument=json.dumps(role["Role"]["AssumeRolePolicyDocument"]))
                
                if(response["ResponseMetadata"]["HTTPStatusCode"] == 200):
                    print("{} - {}arn:aws:iam::{}:{}/{}{}".format(Back.GREEN + "[+]: Valid iam resource found" + Back.RESET, Style.BRIGHT, account.strip("\n"), type, name.strip("\n"), Style.RESET_ALL))

                    if type == "role" and args.checkassumerole:
                        try:
                            response = sts.assume_role(RoleArn="arn:aws:iam::{}:role/{}".format(account, name), RoleSessionName=str(random.randint(1000,9999)))
                            print(response)
                        except Exception as e:
                            #print(e)
                            print("{} - arn:aws:iam::{}:{}/{}".format(Back.YELLOW + "\t[-]: Could not assume role" + Back.RESET, account.strip("\n"), type, name.strip("\n")))

            except Exception as e: 
                if(args.verbose):
                    print("{} - arn:aws:iam::{}:{}/{}".format(Back.RED + "[-]: Invalid iam resource" + Back.RESET, account.strip("\n"), type, name.strip("\n")))


if __name__ == "__main__":
    args = parser.parse_args()

    # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_IAM.html
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns
    resourceTypes = None

    if len(args.resourcetypes) <= 0:
        resourceTypes = ["user", "group", "role"]
    else:
        resourceTypes = args.resourcetypes


    #https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html
    #https://boto3.amazonaws.com/v1/documentation/api/latest/guide/session.html
    session = boto3.Session(aws_access_key_id=args.keyid, aws_secret_access_key=args.accesskey)
    iam = session.client("iam")
    sts = session.client("sts")

    role = iam.get_role(RoleName=args.rolename)

    if args.showpolicy:
        print("="*50)
        print("ARN: {}".format(Back.WHITE + role["Role"]["Arn"] + Back.RESET))
        print("-"*50)
        print(json.dumps(role["Role"]["AssumeRolePolicyDocument"], indent=4))
        print("="*50)

    accounts = io.open(args.ids, "r").readlines()
    names = io.open(args.names, "r").readlines()

    for name in names:
        if re.match(re.compile("(AROA|AIDA|AGPA)"), name.strip("\n")):
            print("{} - {}{}{}".format(Back.LIGHTMAGENTA_EX + "[!]: Resolving unique id" + Back.RESET, Style.BRIGHT, name.strip("\n"), Style.RESET_ALL))
            HandleIAMIdentifier(name.strip("\n"), role, iam, args)
        elif re.match(re.compile("(AKIA|ASIA)"), name.strip("\n")):
            print("{} - {}{}{}".format(Back.CYAN + "[!]: Resolving access key id" + Back.RESET, Style.BRIGHT, name.strip("\n"), Style.RESET_ALL))
            HandleAccessKeyIdentifier(name.strip("\n"), sts, args)
        else:    
            HandleARN(accounts, name, resourceTypes, role, iam, args)