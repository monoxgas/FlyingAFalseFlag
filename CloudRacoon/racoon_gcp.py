import time
import re
import sys
import argparse
import requests
import random
import string
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from pprint import pprint

Description = """                      
 _____ _           _ _____                     
|     | |___ _ _ _| | __  |___ ___ ___ ___ ___ 
|   --| | . | | | . |    -| .'|  _| . | . |   |
|_____|_|___|___|___|__|__|__,|___|___|___|_|_|
    Cloud IP Hunting - Proof of Concept [GCP]         
"""

TLDWhitelist = ['.com', '.net', '.org', '.edu']
SearchRegions = ['us-east1', 'us-central1', 'us-west1', 'us-west2', 'us-east4']

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


def main(arguments):

    parser = argparse.ArgumentParser(description=Description, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('project', help="GCP project to hold assets under")
    parser.add_argument('-l', '--loops', help="Number of loops", default = 50)
    parser.add_argument('-r', '--regions', help="Regions to search (comma delimited)", default = 'us-east1,us-central1,us-west1,us-west2,us-east4')
    parser.add_argument('-lA', '--login-account', help="Service account for authentication")
    parser.add_argument('-lC', '--login-credentials', help="Service account credential file (JSON)")
    parser.add_argument('-q', '--quota', help="Quota limit for max IP addr", default = 8)
    parser.add_argument('-d', '--duplicate-ceiling', help="% of duplicate addresses seen before stopping", default = 70)
    args = parser.parse_args(arguments)

    print(Description)

    driver = get_driver(Provider.GCE)
    engine = driver(
    args.login_account,
    args.login_credentials,
    project=args.project
    )

    print('[+] Connected to GCP.\n')

    regions = args.regions.split(',')

    current_region = random.choice(regions)
    regions.remove(current_region)
    existing_region_addrs = [a for a in engine.ex_list_addresses() if a.region == current_region]
    current_ceiling = args.quota - len(existing_region_addrs)
    print('[+] Switching to {} with {} existing addresses'.format(current_region, len(existing_region_addrs)))

    currently_allocated = []
    previously_seen = []

    for l in range(1, args.loops):
        print('[+] (L{}) Allocating {} new addresses'.format(l, current_ceiling))

        for l in range(1, current_ceiling):
            name = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
            ip = engine.ex_create_address(name, current_region)
            currently_allocated.append(ip)

        print('[+] Checking results')

        matching = [m for m in currently_allocated if m.address in previously_seen]

        for ip in currently_allocated:
            records = get_hostnames(ip.address)

            if ip.address not in matching:
                previously_seen.append(ip.address)

            if not records:
                print('\t- {}'.format(ip.address))
                ip.destroy()
                continue

            print('\t++ {}\n'.format(ip.address))
            pprint(records)
            current_ceiling -= 1

        if (len(matching) / len(currently_allocated)) > (args.duplicate_ceiling / 100):
            print('[!] Duplicate cap ({} percent) has been hit'.format(args.duplicate_ceiling))

            if not regions:
                print('[!] Region list is empty')
                break
                
            current_region = random.choice(regions)
            regions.remove(current_region)
            existing_region_addrs = [a for a in engine.ex_list_addresses() if a.region == current_region]
            current_ceiling = args.quota - len(existing_region_addrs)
            print('[+] Switching to {} with {} existing addresses'.format(current_region, len(existing_region_addrs)))

        currently_allocated = []


    print("\n[+] Done.")


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
