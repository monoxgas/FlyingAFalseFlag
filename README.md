# Flying A False Flag

This repo contains the slides and concept code for my BlackHat USA 2019 talk. This README is a work in progress.

There are three projects in this repo:

* **CloudRacoon** - Tools to hunt for orphaned DNS records by fast cycling cloud IPs
* **PostOffice** - C2 via Exchange EWS services, account piggybacking, and SendGrid
* **Addendum** - C2 concept via VirusTotal sample updates and property extraction

### CloudRacoon - Clound Hunting

I've provided three scripts for AWS, Azure, and GCP hunting. This involves collecting a random IP, checking it's history for interesting records, and either keeping or releasing it. All of these scripts require valid authentication to the specific provider. **AWS is by far the best canidate** for collection. The process and fast and orphaned records are more common. It's common to achieve a 1-3% success rate during the search with a cycle of 100 taking less than a couple minutes.

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

[more soon] 

### PostOffice - EWS C2

This project is provided as a python server side, and C++ client side. It requires the most setup with a valid SendGrid API key, authenticated domain, configured MX record, and inbound Parse hook.

[more soon] 

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

There are also more file types that include data extraction as part of the analysis. PE files, for instance, have their import table extracted and available in any public response.

[more soon] 
