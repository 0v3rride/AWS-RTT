import boto3
import argparse
import io
from colorama import Back, Style
import re


regions = [
    "us-east-2",
    "us-east-1",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-south-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-south-1",
    "ap-northeast-3",
    "ap-northeast-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ca-central-1",
    "ca-west-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-south-1",
    "eu-west-3",
    "eu-south-2",
    "eu-north-1",
    "eu-central-2",
    "il-central-1",
    "me-south-1",
    "me-central-1",
    "sa-east-1"
]

parser = argparse.ArgumentParser(description = "Enumerate ECS information.")
parser.add_argument("-p", "--principals", help="List containing 12 digit AWS account ids, user or role arns.", required=True)
parser.add_argument("-v", "--verbose", action="store_true", help="Give verbose output including invalid resources.", required=False)
parser.add_argument("-k", "--keyid", help="AWS Key ID", required=True)
parser.add_argument("-s", "--accesskey", help="AWS Access Key", required=True)
parser.add_argument("-r", "--regions", action="append", help="Regions to use. Default is all known regions specified by Amazon.", required=False, default=[])

args = parser.parse_args()

session = boto3.Session(aws_access_key_id=args.keyid, aws_secret_access_key=args.accesskey)


principals = io.open(args.principals, "r").readlines()
principals = "".join(principals).replace("\n", " ").split(" ")

if len(args.regions) > 0:
    regions = args.regions

for region in regions:
    #List user, role or root user settings for ecs
    for principal in principals:
        if re.match(re.compile('^\d{12}$'), principal):
            principal = "arn:aws:iam::{}:root".format(principal)

        try:
            ecs = session.client("ecs", region_name=region)
            #https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs/client/list_account_settings.html
            response = ecs.list_account_settings(principalArn=principal, effectiveSettings=True)
            
            if(response["ResponseMetadata"]["HTTPStatusCode"] == 200):
                print("{} - {}{}{}".format(Back.GREEN + "[+]: Account settings for" + Back.RESET, Style.BRIGHT, principal, Style.RESET_ALL))

                for setting in response["settings"]:
                    print("{}\t[*]:{}{} - {}{}{}".format(Back.CYAN, setting["name"], Back.RESET, Style.BRIGHT, setting["value"], Style.RESET_ALL))

        except Exception as e:
            print(e)
