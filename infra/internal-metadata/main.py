"""
VulnForge Lab — Internal Metadata Service
Simulates AWS EC2 IMDSv1 (169.254.169.254) for SSRF testing.
Only accessible from internal_net; not reachable by the scanner directly.

Endpoints mirror real IMDSv1 structure so scanner SSRF payloads targeting
"http://169.254.169.254/latest/meta-data/" actually get a realistic response.
"""

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

app = FastAPI()

FAKE_METADATA = {
    "ami-id": "ami-deadbeef",
    "ami-launch-index": "0",
    "hostname": "ip-10-0-1-42.ec2.internal",
    "instance-id": "i-deadbeef12345678",
    "instance-type": "t3.micro",
    "local-hostname": "ip-10-0-1-42.ec2.internal",
    "local-ipv4": "10.0.1.42",
    "public-hostname": "",
    "public-ipv4": "1.2.3.4",
    "placement/availability-zone": "us-east-1a",
    "placement/region": "us-east-1",
    "security-groups": "default",
    "iam/security-credentials/": "vulnforge-role",
}

FAKE_IAM_CREDENTIALS = """{
  "Code" : "Success",
  "LastUpdated" : "2024-01-01T00:00:00Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token" : "AQoXnyc4lcK4w4OIaYnuFT5//////////wEaoAK1wvxJY12r2IKwFhZg==",
  "Expiration" : "2099-01-01T00:00:00Z"
}"""

FAKE_USERDATA = """#!/bin/bash
# This is a fake user-data script for SSRF testing only
export DB_PASSWORD=vulnforge_ssrf_test_password
export API_KEY=vulnforge_ssrf_test_api_key_12345
echo "VulnForge SSRF test successful"
"""


@app.get("/latest/meta-data/")
def list_metadata():
    keys = "\n".join(FAKE_METADATA.keys())
    return PlainTextResponse(keys)


@app.get("/latest/meta-data/{path:path}")
def get_metadata(path: str):
    # IAM credentials endpoint
    if path == "iam/security-credentials/vulnforge-role":
        return PlainTextResponse(FAKE_IAM_CREDENTIALS)

    value = FAKE_METADATA.get(path)
    if value is None:
        from fastapi import HTTPException
        raise HTTPException(404, "Not found")
    return PlainTextResponse(str(value))


@app.get("/latest/user-data")
def get_userdata():
    return PlainTextResponse(FAKE_USERDATA)


@app.get("/health")
def health():
    return {"status": "ok", "service": "internal-metadata"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=80)
