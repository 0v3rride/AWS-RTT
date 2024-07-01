import boto3
import argparse
import io
from colorama import Back, Style


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

parser = argparse.ArgumentParser(description = "Enumerate EC2 information.")
parser.add_argument("-i", "--ids", help="List containing 12 digit AWS account ids.", required=True)
parser.add_argument("-v", "--verbose", action="store_true", help="Give verbose output including invalid resources.", required=False)
parser.add_argument("-k", "--keyid", help="AWS Key ID", required=True)
parser.add_argument("-s", "--accesskey", help="AWS Access Key", required=True)
parser.add_argument("-r", "--regions", action="append", help="Regions to use. Default is all known regions specified by Amazon.", required=False, default=[])

args = parser.parse_args()

session = boto3.Session(aws_access_key_id=args.keyid, aws_secret_access_key=args.accesskey)

accounts = io.open(args.ids, "r").readlines()
accounts = "".join(accounts).replace("\n", " ").split(" ")

if len(args.regions) > 0:
    regions = args.regions

for region in regions:
    for account in accounts:
        try:
            ecr = session.client("ecr", region_name=region)
            response = ecr.describe_repositories(registryId=account)
            print(response)
        except Exception as e:
            print(e)