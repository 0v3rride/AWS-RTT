import boto3
import argparse
import io
from colorama import Back, Style
import botocore.exceptions


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

#check regions
for region in regions:
    try:
        ec2 = session.client("ec2", region_name=region)
    

        #list amis
        for account in accounts:
            response = ec2.describe_images(ExecutableUsers=["all"], Owners=["{}".format(account)])
            
            if(len(response["Images"]) > 0):
                print("{} for - {}{}:{}".format(Back.GREEN + "[+]: AMIs found" + Back.RESET, Style.BRIGHT, account, region))
                for image in response["Images"]:
                    print("\t- arn:aws:ec2:{}:{}:image/{}".format(region, account, image["ImageId"]))

                    if "Description" in image:
                        print("\t\t- Description: {}".format(image["Description"]))

                    if "ImageOwnerAlias" in image:
                        print("\t\t- Owner Alias: {}".format(image["ImageOwnerAlias"]))
            elif(len(response["Images"]) <= 0 and args.verbose):
                print("{} for - {}:{}:{}".format(Back.RED + "[-]: No AMIs found" + Back.RESET, account, region, response["Images"]))


        #list ebs snapshots
        for account in accounts:
            response = ec2.describe_snapshots(OwnerIds=["{}".format(account)], RestorableByUserIds=["all"])
            
            if(len(response["Snapshots"]) > 0):
                print("{} for - {}{}:{}".format(Back.GREEN + "[+]: EBS snapshots found" + Back.RESET, Style.BRIGHT, account, region))
                for snapshot in response["Snapshots"]:
                    print("\t- arn:aws:ec2:{}:{}:snapshot/{}".format(region, account, snapshot["SnapshotId"]))

                    if "Description" in snapshot:
                        print("\t\t- Description: {}".format(snapshot["Description"]))

                    if "OwnerAlias" in snapshot:
                        print("\t\t- Owner Alias: {}".format(snapshot["OwnerAlias"]))
            elif(len(response["Snapshots"]) <= 0 and args.verbose):
                print("{} for - {}:{}:{}".format(Back.RED + "[-]: No EBS snapshots found" + Back.RESET, account, region, response["Snapshots"]))


        #list instances
        for account in accounts:
            response = ec2.describe_instances(Filters=[{"Name": "owner-id", "Values":["{}".format(account)]}])
            
            if(len(response["Reservations"]) > 0):
                print("{} for - {}{}:{}:\n\n{}{}".format(Back.GREEN + "[+]: EC2 instances found" + Back.RESET, Style.BRIGHT, account, region, response["Reservations"], Style.RESET_ALL))
            elif(len(response["Reservations"]) <= 0 and args.verbose):
                print("{} for - {}:{}:{}".format(Back.RED + "[-]: No EC2 instances found" + Back.RESET, account, region, response["Reservations"]))

    except botocore.exceptions.ClientError as ce:
        if args.verbose:
            print(Back.RED + "{}".format(ce) + Back.RESET + " - ec2:{}".format(region))
