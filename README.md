# Rainforest
Amazon cloud scanning tool


## Key Capabilities for Rainforest:

1. AWS Reconnaissance

Enumerate public S3 buckets (misconfigured permissions)

Identify IAM roles & policies (weak policies, privilege escalation paths)

Detect publicly exposed EC2 instances (open ports, weak auth)

Find CloudFront misconfigurations (leaking origin servers)

Analyze Lambda functions (hardcoded secrets, SSRF paths)

Identify exposed API Gateways (open API endpoints)



2. Network & Web Scanning

Scan for open ports (like nmap)

Test for default credentials on exposed services

Look for server misconfigurations (CORS, SSRF, RCE)

Detect AWS metadata service abuse (IMDSv1 vulnerabilities)



3. Privilege Escalation Paths

Test for over-permissioned IAM roles

Identify SSRF opportunities to steal credentials

Check Lambda and ECS task permissions for escalation



4. Vulnerability Scanning & Exploitation

Auto-check for CVE-related vulnerabilities (log4j, SSRF, etc.)

Scan for publicly exposed AWS keys (like trufflehog but focused)

Test Cognito misconfigurations (account takeover)



5. Evasion & Stealth Mode

Rotate User-Agent & IPs to avoid detection

Use Socks5/Tor proxy support for anonymization

Implement rate limiting to avoid triggering AWS GuardDuty




Tech Stack & Implementation

Python (boto3, nmap, requests, scapy)

Rust/Go (for high-performance scanning modules)

Modular Design (allow users to plug in specific scan modules)

---

PoC: Rainforest AWS Recon & Vulnerability Scanner

Focus Areas:
✅ AWS Recon (EC2, S3, IAM, Lambda, API Gateway, CloudFront, Cognito, etc.)
✅ Vulnerability Scanning (open ports, weak credentials, SSRF, CVEs, metadata abuse)
✅ Key Retrieval & Secrets Discovery (S3 leaks, GitHub, Public Repos, ENV files, etc.)
✅ Stealth Features (Rate Limiting, Proxy Support, User-Agent Rotation, Timing Jitter)



---

initial PoC in Python and ensures it follows real-world evasion techniques to avoid firewalls, EDRs, and AWS-specific monitoring tools like GuardDuty.


```python
import boto3
import requests
import socket
import json
import re
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

class RainforestScanner:
    def __init__(self, aws_access_key=None, aws_secret_key=None):
        print("[DEBUG] Initializing RainforestScanner...")
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.vulnerabilities = []
        try:
            self.s3_client = boto3.client("s3", aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
            self.iam_client = boto3.client("iam", aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
            self.ec2_client = boto3.client("ec2", aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
            print("[DEBUG] AWS clients initialized successfully.")
        except (NoCredentialsError, PartialCredentialsError) as e:
            print(f"[-] AWS credential error: {e}")
            exit()
    
    def scan_s3_buckets(self):
        print("[+] Scanning for publicly accessible S3 buckets...")
        try:
            buckets = self.s3_client.list_buckets()
            print(f"[DEBUG] Found {len(buckets.get('Buckets', []))} buckets.")
            for bucket in buckets.get('Buckets', []):
                bucket_name = bucket['Name']
                print(f"[+] Checking {bucket_name}...")
                response = requests.get(f"https://{bucket_name}.s3.amazonaws.com", timeout=3)
                if response.status_code == 200:
                    print(f"[!] Publicly accessible S3 bucket found: {bucket_name}")
                    self.vulnerabilities.append(f"Public S3: {bucket_name}")
        except ClientError as e:
            print(f"[-] AWS Error: {e}")
    
    def scan_ec2_instances(self):
        print("[+] Enumerating EC2 instances...")
        try:
            instances = self.ec2_client.describe_instances()
            print(f"[DEBUG] Retrieved EC2 instances data.")
            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    public_ip = instance.get('PublicIpAddress')
                    if public_ip:
                        print(f"[+] Found EC2 Instance: {instance['InstanceId']} - Public IP: {public_ip}")
                        self.scan_open_ports(public_ip)
        except ClientError as e:
            print(f"[-] AWS Error: {e}")
    
    def scan_open_ports(self, ip):
        print(f"[+] Scanning open ports on {ip}...")
        for port in [22, 80, 443, 3306, 6379, 8080]:
            try:
                with socket.create_connection((ip, port), timeout=1):
                    print(f"[!] Open port detected: {ip}:{port}")
                    self.vulnerabilities.append(f"Open Port: {ip}:{port}")
            except (socket.timeout, ConnectionRefusedError):
                pass
    
    def scan_iam_policies(self):
        print("[+] Checking IAM roles and policies for privilege escalation...")
        try:
            users = self.iam_client.list_users()
            print(f"[DEBUG] Found {len(users.get('Users', []))} IAM users.")
            for user in users.get('Users', []):
                print(f"[+] User: {user['UserName']}")
                policies = self.iam_client.list_attached_user_policies(UserName=user['UserName'])
                for policy in policies.get('AttachedPolicies', []):
                    print(f"    - {policy['PolicyName']}")
        except ClientError as e:
            print(f"[-] AWS Error: {e}")
    
    def scan_metadata_service(self):
        print("[+] Checking AWS metadata service for potential leaks...")
        try:
            response = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/", timeout=2)
            if response.status_code == 200:
                print("[!] Instance has IAM credentials exposed via metadata API!")
                self.vulnerabilities.append("IAM Credentials Exposed via Metadata API")
        except requests.exceptions.RequestException:
            print("[-] Metadata service appears to be secured.")
    
    def scan_keys_and_secrets(self):
        print("[+] Searching for exposed AWS keys and secrets in known locations...")
        possible_keys = []
        for file in ["/etc/environment", "config.json"]:
            try:
                with open(file, "r") as f:
                    content = f.read()
                    keys = re.findall(r'AKIA[0-9A-Z]{16}', content)
                    possible_keys.extend(keys)
                    print(f"[DEBUG] Found {len(keys)} possible keys in {file}.")
            except FileNotFoundError:
                pass
        
        if possible_keys:
            print(f"[!] Exposed AWS Keys Found: {possible_keys}")
            self.vulnerabilities.append(f"Exposed AWS Keys: {possible_keys}")
        else:
            print("[-] No exposed AWS keys found.")
    
    def run_all_scans(self):
        print("[DEBUG] Running all scans...")
        self.scan_s3_buckets()
        self.scan_ec2_instances()
        self.scan_iam_policies()
        self.scan_metadata_service()
        self.scan_keys_and_secrets()
        
        if self.vulnerabilities:
            print("\n[!] Vulnerabilities Found:")
            for vuln in self.vulnerabilities:
                print(f" - {vuln}")
        else:
            print("[+] No major vulnerabilities detected.")

if __name__ == "__main__":
    print("[DEBUG] Starting RainforestScanner...")
    scanner = RainforestScanner()
    scanner.run_all_scans()
    print("[DEBUG] Scan process completed.")
```

## v2
As you can see I'm working through the bugs on this.
However, KubeCloudV2 was successful was fully developed on all platforms.
I have no doubt this will be too.

Many Thanks,
DeadmanXXXII


