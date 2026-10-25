# CloudSentinel

**A lightweight CLI security auditor for AWS accounts — scans S3, IAM, EC2/Security Groups, and CloudTrail for common misconfigurations and reports findings ranked by severity.**

> Built as a coursework/learning project to understand cloud security auditing from first principles — inspired by tools like Prowler and ScoutSuite, scoped down to be fully readable and extensible end-to-end.

---

## What It Does

CloudSentinel connects to an AWS account using **read-only credentials**, runs a set of independent security checks against S3, IAM, EC2/Security Groups, and CloudTrail, and produces a severity-ranked report of anything misconfigured — along with why it matters and how to fix it.

It never modifies the target account. It only reads.

## How It Works

1. **Authenticate** — a `boto3` session is created using an IAM role or access keys you provide (least-privilege policy included in `iam/scanner-readonly-policy.json`).
2. **Run checks** — each check is a small, independent unit that queries one specific AWS API (e.g., `list_buckets`, `get_account_summary`) and evaluates the result against a known-bad pattern (e.g., "is this bucket publicly readable?").
3. **Collect findings** — every check returns a structured `Finding` (resource, status, severity, explanation, remediation) regardless of which service it checked, so results from S3, IAM, EC2, and CloudTrail all flow through the same pipeline.
4. **Report** — findings are sorted by severity and rendered as a colored terminal table, and optionally exported as JSON (for scripting/CI) or a standalone HTML report.

The architecture deliberately keeps **checks** (produce data) and **reporters** (format data) decoupled — neither needs to know about the other, which makes it straightforward to add a new check or a new output format without touching existing code.

## Checks Performed

| ID | Service | Check | Severity |
|---|---|---|---|
| S3.1 | S3 | Bucket allows public read/write via ACL or policy | High |
| S3.2 | S3 | Server-side encryption not enabled | Medium |
| S3.3 | S3 | Versioning disabled | Low |
| S3.4 | S3 | Access logging disabled | Low |
| IAM.1 | IAM | Console-access user without MFA | High |
| IAM.2 | IAM | Policy with wildcard Action + Resource (`*`/`*`) | High |
| IAM.3 | IAM | Access key older than 90 days | Medium |
| IAM.4 | IAM | Root account used within last 30 days | High |
| EC2.1 | EC2/SG | Security group open to `0.0.0.0/0` on port 22/3389 | High |
| EC2.2 | EC2/SG | Security group open to `0.0.0.0/0` on DB ports | High |
| EC2.3 | EC2 | Unencrypted EBS volume | Medium |
| CT.1 | CloudTrail | No trail enabled | High |
| CT.2 | CloudTrail | Trail not multi-region | Medium |
| CT.3 | CloudTrail | Log file validation disabled | Low |

*(A mapping to CIS AWS Foundations Benchmark control numbers is on the roadmap.)*

## Tech Stack

- **Python 3.11+**
- **[boto3](https://boto3.amazonaws.com/)** — AWS SDK for Python
- **[click](https://click.palletsprojects.com/)** — CLI framework
- **[rich](https://github.com/Textualize/rich)** — colored terminal tables/output
- **[Jinja2](https://jinja.palletsprojects.com/)** — HTML report templating
- **[moto](https://github.com/getmoto/moto)** — mocked AWS services for testing
- **[pytest](https://pytest.org/)** — test runner

## Getting Started

### 1. Clone and install

```bash
git clone https://github.com/palxsh01/CloudSentinel.git
cd CloudSentinel
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Create a read-only IAM role

Attach the policy in `iam/scanner-readonly-policy.json` to an IAM user or role. It grants exactly the 30 read actions the checks call — `List*`/`Get*`/`Describe*`, plus `iam:GenerateCredentialReport`, which only builds a report of existing data (AWS's own `SecurityAudit` policy grants it). Nothing in it can modify your account. `tests/test_policy.py` records every AWS call a full scan makes and fails if the policy grants anything more or less.

### 3. Configure credentials

Use any standard `boto3` credential source — environment variables, `~/.aws/credentials`, or an assumed role:

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

## Usage

```bash
# Run a full scan, print to terminal
python -m scanner.main scan

# Export findings as JSON
python -m scanner.main scan --output json --file findings.json

# Generate an HTML report
python -m scanner.main scan --output html --file report.html

# Run only checks for a specific service
python -m scanner.main scan --service s3

# Use a named profile and session region
python -m scanner.main scan --profile audit --region eu-west-1
```

| Option | Values | Default |
|---|---|---|
| `--service` | `s3`, `iam`, `ec2`, `cloudtrail` | all |
| `--output` | `terminal`, `json`, `html` | `terminal` |
| `--file` | path (needs `--output json` or `html`) | stdout |
| `--profile`, `--region` | any boto3 profile / region | boto3 defaults |

EC2 and CloudTrail checks sweep every enabled region regardless of `--region`; S3 reads each bucket in its own region.

**Exit code:** `1` when any HIGH finding exists, `0` otherwise — so a CI step fails on high-severity issues. A check that cannot run (e.g. `AccessDenied`) is listed as a warning rather than silently skipped; in JSON/HTML mode it also goes to stderr and into the report's `errors`.

## Sample Output

From the end-to-end test, against a `moto`-mocked account with every misconfiguration planted (`pytest -s -k demo`):

```
CloudSentinel scan report — account: 123456789012
 Severity  Check  Resource                          Detail
 HIGH      CT.1   account                           2 trail(s) exist but none is logging
 HIGH      EC2.1  sg-357693cfcfce8771e (...-open)   us-east-1: open to the internet on 22 (SSH)
 HIGH      EC2.2  sg-357693cfcfce8771e (...-open)   us-east-1: open to the internet on 3306 (MySQL)
 HIGH      IAM.1  cloudsentinel-no-mfa              console password set, no MFA device
 HIGH      IAM.2  arn:aws:iam::...:policy/...-admin allows Action '*' on Resource '*'
 HIGH      IAM.4  <root_account>                    root used via console sign-in 2d ago
 HIGH      S3.1   cloudsentinel-public-bucket       ACL grants READ to everyone
 MEDIUM    CT.2   cloudsentinel-trail               records only us-east-1
 MEDIUM    EC2.3  vol-31daffa1355161fae             us-east-1: 1 GiB volume, available, unencrypted
 MEDIUM    IAM.3  AKIARZPUZDIKCQ5SBECM              cloudsentinel-no-mfa's key is 91 days old
 MEDIUM    S3.2   cloudsentinel-public-bucket       no default encryption configured
 LOW       CT.3   cloudsentinel-trail               log file validation is off
 LOW       S3.3   cloudsentinel-public-bucket       versioning is never enabled
 LOW       S3.4   cloudsentinel-public-bucket       server access logging is off
14 findings: 7 High, 4 Medium, 3 Low
```

## Testing

All checks are unit-tested against **mocked** AWS responses using `moto`, so tests run without real credentials or any risk of touching a live account:

```bash
pytest tests/
```

## Validating Against a Vulnerable Sandbox

Detection accuracy is verified two ways. Every check is unit-tested against `moto`-mocked AWS (above). Beyond that, CloudSentinel is validated against a deliberately misconfigured AWS sandbox account — an open S3 bucket, an over-permissive security group, an MFA-less IAM user and friends — to confirm every planted issue is flagged, with no false negatives on the known set.

> **Status (2026-10-22):** validated on a real account, scanning as a role holding only `iam/scanner-readonly-policy.json`. Every planted issue was flagged (12/12 findings across S3.1, S3.3, S3.4, IAM.1, IAM.2, EC2.1–EC2.3, CT.1–CT.3), with no unexpected findings and no `AccessDenied` errors; a us-west-2 bucket was read correctly from an ap-south-1 session. IAM.4 fired on a genuine root sign-in. IAM.3 (90-day-old key) and S3.2 (AWS encrypts new buckets by default since 2023) can't be planted on a fresh resource, so those two rely on the `moto` suite.

## Roadmap

- [ ] CIS AWS Foundations Benchmark control mapping (`docs/cis-mapping.md`)
- [ ] Risk scoring (weighted overall account score)
- [ ] Diff mode — compare two scans and show what changed
- [ ] Additional service coverage (RDS, Lambda, VPC)

## Disclaimer

This tool is intended for auditing AWS accounts **you own or have explicit permission to scan**. It performs read-only operations, but running it against infrastructure you don't control or lack authorization for may violate AWS's terms of service and applicable law. Built for educational purposes as part of university coursework.

## License

MIT
