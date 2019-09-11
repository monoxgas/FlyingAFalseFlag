# Flying A False Flag

This repo contains the slides and concept code for my BlackHat USA 2019 talk about Command and Control.

There are three projects in this repo:

* **CloudRacoon** - Tools to hunt for orphaned DNS records by fast cycling cloud IPs
* **PostOffice** - C2 via Exchange EWS services, account piggybacking, and SendGrid
* **Addendum** - C2 concept via VirusTotal sample updates and property extraction

### CloudRacoon - Clound Hunting

I've provided three scripts for AWS, Azure, and GCP hunting. This involves collecting a random IP, checking it's history for interesting records, and either keeping or releasing it. All of these scripts require valid authentication to the specific provider. **AWS is by far the best canidate** for collection. The process is fast and there are many orphaned records. It's not uncommon to achieve a 1-3% success rate during a cycle of 100 IPs (taking less than a couple minutes).

```
> python racoon_aws.py us-west-1 -aK <access_key> -sK <secret_key>

[+] Connected to AWS. Hunting in us-west-1 ... (max: 100)

        +++ 54.241.90.186 : docker.wooagency.com
        +++ 52.8.1.47 : next-donate.sanguinebio.com
        = 52.52.237.229 : 13.52.45.201.hczvxliealbqzvdy.com
        
> python racoon_aws.py -l all -aK <access_key> -sK <secret_key>

[+] us-west-1 has 3

13.52.14.26     :
52.8.1.47       : next-donate.sanguinebio.com
54.241.90.186   : docker.wooagency.com
``` 

### PostOffice - EWS C2

This project is provided as a python server side, and C++ client side. It requires the most setup with a valid SendGrid API key, authenticated domain, configured MX record, and inbound parse hook.

#### Setup
1. Setup a SendGrid account and add an authenticated domain
2. Select an email address to use, such as `c2@[mydomain.com]`
3. Configure the MX record for your mail domain to point to `mx.sendgrid.net`
4. Choose a public host for the C2 server, and configure an inbound parse hook in SendGrid (`http://[myserver.com]/inbox`)

#### Server
A Python 3 script with uses the `bottle` HTTP library for inbound hooks, and the `sendgrid` library for outbound emails.

1. Put your SG API key and email into `post_office.py`
2. Execute the server on your public host to wait for a callback
```
> python post_office.py

 _____         _   _____ ___ ___ _         
|  _  |___ ___| |_|     |  _|  _|_|___ ___ 
|   __| . |_ -|  _|  |  |  _|  _| |  _| -_|
|__|  |___|___|_| |_____|_| |_| |_|___|___|
        EWS Mail C2 - Proof of Concept

# 
``` 

#### Client
A Visual Studio C++ project which compiles into an EXE. It uses WinInet for requests, and is capable of extracting
mailbox credentials from the Windows credential vault for authentication.

1. Place your target email address into `client\Exchanger\Exchanger.cpp`.
2. Build the solution and execute. You should recieve a new "callback" on the server.

#### Notes
- The actual C2 data is Base64 encoded and placed inside a mail header. This means email contents can be benign to slip past filtering.
- Email headers, and emails in general, have various size limitations depending on the provider. For real-world use, an additional chunking mechanic would likely be needed.


### Addendum - VirusTotal C2

This is a simple python script the masquerades as both the server in the client. It runs in two phases:

1. Random data is generated and packing into the `HyperlinkBase` property of an office document.
2. The document is uploaded to VT and the script waits until analysis finishes
3. A comment is made on the new sample using the account credentials provided

----

4. The "client" code now pulls a list of comments using only the username of the account
5. The sample is identified, downloaded, and the random data is extracted.
6. The data is checked to ensure it matches

Naturally these steps could be performed in seperate code, with each one uploading, tagging, and pulling down samples.

#### Notes
- There are also more file types that include data extraction as part of the analysis. PE files, for instance, have their import table extracted and available in any public response.
- Outside of samples, commands and profile information could be used as their own C2 channel
