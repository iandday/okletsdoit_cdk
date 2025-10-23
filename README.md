# okletsdoit-cdk

Infrastructure as code for the okletsdoit application using AWS CDK (Python).

This repository provisions S3 buckets and CloudFront for static/media files and an RDS PostgreSQL instance inside a VPC. The stack is intended to follow practical best practices for production: private subnets, encrypted storage, automated backups, and credentials stored in Secrets Manager.

## Contents

- `app.py` — CDK app entrypoint
- `okletsdoit_cdk/` — CDK stack source
- `Constructs/` — additional Construct definitions
- `tests/` — unit tests



