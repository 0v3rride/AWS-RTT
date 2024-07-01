import boto3
import argparse
import io
from colorama import Back, Style
import re
import botocore.exceptions

accounts = ""

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

snapshotTypes = [
    "automated",
    "manual",
    "shared",
    "public",
    "awsbackup"
]

parser = argparse.ArgumentParser(description = "Enumerate EC2 information.")
parser.add_argument("-i", "--ids", help="List containing 12 digit AWS account ids.", required=False)
parser.add_argument("-v", "--verbose", action="store_true", help="Give verbose output including invalid resources.", required=False)
parser.add_argument("-k", "--keyid", help="AWS Key ID", required=True)
parser.add_argument("-s", "--accesskey", help="AWS Access Key", required=True)
parser.add_argument("-r", "--regions", action="append", help="Regions to use. Default is all known regions specified by Amazon.", required=False, default=[])
parser.add_argument("-b", "--snapshottypes", action="append", help="Snapshots types to look for.", required=False, default=[])
parser.add_argument("-c", "--checkinstance", action="store_true", help="Check if there is an instance running with the same name as the snapshot.", required=False)

args = parser.parse_args()

session = boto3.Session(aws_access_key_id=args.keyid, aws_secret_access_key=args.accesskey)


if args.ids:
    accounts = io.open(args.ids, "r").readlines()
    accounts = "".join(accounts).replace("\n", " ").split(" ")



if len(args.regions) > 0:
    regions = args.regions

if len(args.snapshottypes) > 0:
    snapshotTypes = args.snapshottypes



#https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.ARN.html
for region in regions:
    rds = session.client("rds", region_name=region)

    for type in snapshotTypes:
        #Look for public snapshots - arn:aws:rds:<region>:<account>:snapshot:<name>

        if args.ids:
            for id in accounts:
                if re.match("^\d{12}$", id):
                    try: 
                        #https://stackoverflow.com/questions/39201093/how-to-use-boto3-pagination               
                        response = rds.describe_db_snapshots(IncludePublic=True, SnapshotType=type)

                        while "Marker" in response:
                            for dbsnapshot in response["DBSnapshots"]:
                                if dbsnapshot["DBSnapshotIdentifier"].find(id) > -1:
                                    print("{}[+]: {} Snapshot Found:{} {}".format(Back.GREEN, type, Style.RESET_ALL, dbsnapshot["DBSnapshotIdentifier"]))

                                    if args.checkinstance:
                                        try:
                                            Instance = rds.describe_db_instance(DBInstanceIdentifier=dbsnapshot["DBInstanceIdentifier"])
                                            print("\t{}[+] Found DB Instance:{} {}".format(Back.BLUE, Style.RESET_ALL, dbsnapshot["DBInstanceIdentifier"]))
                                        except Exception as e:
                                            if args.verbose:
                                                print("\t{}[-] Invalid DB Instance:{} {}".format(Back.RED, Style.RESET_ALL, dbsnapshot["DBInstanceIdentifier"]))
                                            continue
                            
                            response = rds.describe_db_snapshots(IncludePublic=True, SnapshotType=type, Marker=response["Marker"])
                    
                    except Exception as e:
                        print(e)
        else:
            try: 
                #https://stackoverflow.com/questions/39201093/how-to-use-boto3-pagination               
                response = rds.describe_db_snapshots(IncludePublic=True, SnapshotType=type)

                while "Marker" in response:
                    for dbsnapshot in response["DBSnapshots"]:
                        print("{}[+]: {} Snapshot Found:{} {}".format(Back.GREEN, type, Style.RESET_ALL, dbsnapshot["DBSnapshotIdentifier"]))

                        if args.checkinstance:
                            try:
                                Instance = rds.describe_db_instances(DBInstanceIdentifier=dbsnapshot["DBInstanceIdentifier"])
                                print("\t{}[+] Found DB Instance:{} {}".format(Back.BLUE, Style.RESET_ALL, dbsnapshot["DBInstanceIdentifier"]))
                            except Exception as e:
                                if args.verbose:
                                    print("\t{}[-] Invalid DB Instance:{} {}".format(Back.RED, Style.RESET_ALL, dbsnapshot["DBInstanceIdentifier"]))
                                continue
                            
                    response = rds.describe_db_snapshots(IncludePublic=True, SnapshotType=type, Marker=response["Marker"])
                    
            except Exception as e:
                print(e)
