import re, os, sys, argparse
import boto3
from pprint import pprint
import requests
import random
import time

Description = """                      
 _____ _           _ _____                     
|     | |___ _ _ _| | __  |___ ___ ___ ___ ___ 
|   --| | . | | | . |    -| .'|  _| . | . |   |
|_____|_|___|___|___|__|__|__,|___|___|___|_|_|
    Cloud IP Hunting - Proof of Concept [AWS]         
"""

TLDWhitelist = ['.com', '.net', '.org', '.edu']
AWSRegions = ['us-east-2','us-east-1','us-west-1','us-west-2','ca-central-1','eu-central-1','eu-west-1','eu-west-2','eu-west-3','eu-north-1']

Session = None
CSRFToken = None

def get_hostnames(address):
    global Session
    global CSRFToken

    if not Session:
        #print('[+] Opening session for Security Trails ...')

        Session = requests.Session()
        response = Session.get('https://securitytrails.com/list/ip/1.1.1.1')
        CSRFToken = re.findall(r'csrf_token = "(\S+?)"', response.text)[0]

    response = Session.post(f'https://securitytrails.com/app/api/v1/list?ipv4={address}', json = {'_csrf_token' : CSRFToken})

    if response.status_code != 200:
        print('[!] SecurityTrails request failed!')
        print(response.text)
        sys.exit(1)

    records = response.json().pop('records', [])

    if records:
        return [r['hostname'] for r in records]

    return []

def list_current_addresses(args):
    if args.region == 'all':
        regions = AWSRegions
    else:
        regions = [args.region]

    for region in regions:

        engine = boto3.client(
        'ec2',
        aws_access_key_id = args.access_key,
        aws_secret_access_key = args.secret_key,
        region_name = region
        )

        current_addresses = [a['PublicIp'] for a in engine.describe_addresses().pop('Addresses', [])]

        if len(current_addresses) > 1:
            print('\n[+] {} has {}\n'.format(region, len(current_addresses)))

            for addr in current_addresses:
                hostnames = get_hostnames(addr)
                print('{:15} : {}'.format(addr, '|'.join(hostnames)))

    print('')

def main(arguments):

    parser = argparse.ArgumentParser(description=Description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('region', choices=AWSRegions + ['all'], help="AWS Region to search")
    parser.add_argument('-c', '--count', type=int, help="Number of IPs to try", default = 100)
    parser.add_argument('-l', '--list', help="List current IP info", action="store_true")
    parser.add_argument('-aK', '--access-key', help="AWS access key")
    parser.add_argument('-sK', '--secret-key', help="AWS secret key")
    args = parser.parse_args(arguments)

    print(Description)

    if args.list:
        return list_current_addresses(args)

    if args.region == 'all':
        print("[!] 'All' is not valid when hunting")
        return

    engine = boto3.client(
    'ec2',
    aws_access_key_id = args.access_key,
    aws_secret_access_key = args.secret_key,
    region_name = args.region
    )

    print('\n[+] Connected to AWS. Hunting in {} ... (max: {})\n'.format(args.region, args.count))

    for l in range(0, args.count):

        eip = engine.allocate_address(Domain='vpc')
        address = eip['PublicIp']
        allocation_id = eip['AllocationId']

        hostnames = get_hostnames(address)

        if hostnames:
            valid_tld = any([[h for h in hostnames if h.endswith(tld)] for tld in TLDWhitelist])
            obvious_bad = [h for h in hostnames if h.count('.') > 4]

            if not valid_tld or obvious_bad:
                print('\t= {} : {}'.format(address, hostnames[0]))
            else:
                print('\t+++ {} : {}'.format(address, '|'.join(hostnames)))
                continue

        print('\t- {:15}'.format(address), end = '\r')
        engine.release_address(AllocationId=allocation_id)

    print('\n')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
