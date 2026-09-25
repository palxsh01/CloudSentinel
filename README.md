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

*(See `docs/cis-mapping.md` for the corresponding CIS AWS Foundations Benchmark control numbers, where mapped.)*

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

\`\`\`bash
git clone https://github.com/palxsh01/CloudSentinel.git
cd CloudSentinel
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
\`\`\`

### 2. Create a read-only IAM role

Attach the policy in `iam/scanner-readonly-policy.json` to an IAM user or role. This grants only the `List*`/`Get*`/`Describe*` permissions CloudSentinel needs — it can never modify anything in your account.

### 3. Configure credentials

Use any standard `boto3` credential source — environment variables, `~/.aws/credentials`, or an assumed role:

\`\`\`bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
\`\`\`

## Usage

\`\`\`bash
# Run a full scan, print to terminal
python -m scanner.main scan

# Export findings as JSON
python -m scanner.main scan --output json --file findings.json

# Generate an HTML report
python -m scanner.main scan --output html --file report.html

# Run only checks for a specific service
python -m scanner.main scan --service s3
\`\`\`

## Sample Output

\`\`\`
CloudSentinel Scan Report — account: 123456789012
──────────────────────────────────────────────────────────
[HIGH]   S3.1   my-public-bucket        Bucket allows public read access
[HIGH]   IAM.1  jdoe                    Console user has no MFA enabled
[MEDIUM] IAM.3  arn:aws:iam::...:key/1  Access key is 142 days old
[LOW]    S3.3   my-data-bucket          Versioning is disabled
──────────────────────────────────────────────────────────
4 findings: 2 High, 1 Medium, 1 Low
\`\`\`

## Testing

All checks are unit-tested against **mocked** AWS responses using `moto`, so tests run without real credentials or any risk of touching a live account:

\`\`\`bash
pytest tests/
\`\`\`

## Validating Against a Vulnerable Sandbox

Detection accuracy is verified two ways. Every check is unit-tested against `moto`-mocked AWS (above). Beyond that, CloudSentinel is validated against a deliberately misconfigured AWS sandbox account — an open S3 bucket, an over-permissive security group, an MFA-less IAM user and friends — to confirm every planted issue is flagged, with no false negatives on the known set.

> **Status:** the sandbox validation run is pending an AWS account (tracked in `backlog.md`). The `moto` suite is the current correctness gate.

## Roadmap

- [ ] CIS AWS Foundations Benchmark control mapping (`docs/cis-mapping.md`)
- [ ] Risk scoring (weighted overall account score)
- [ ] Diff mode — compare two scans and show what changed
- [ ] Additional service coverage (RDS, Lambda, VPC)

## Disclaimer

This tool is intended for auditing AWS accounts **you own or have explicit permission to scan**. It performs read-only operations, but running it against infrastructure you don't control or lack authorization for may violate AWS's terms of service and applicable law. Built for educational purposes as part of university coursework.

## License

MIT
