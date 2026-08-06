/**
 * DevSecOps Module
 * Covers: CI/CD attacks, supply chain, IaC misconfig, container security, secrets in code
 * Difficulty: Beginner → Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('devsecops/index', {
    title: 'DevSecOps',
    user: req.session?.user,
  });
});

// D1: Secrets in Git (Beginner)
router.get('/git-secrets', (req, res) => {
  res.json({
    vuln: 'D1: Secrets Committed to Git History',
    level: 'Beginner',
    description: 'Developers committed secrets. Use git log -p or trufflehog to find them.',
    commits: [
      {
        hash: 'a1b2c3d',
        message: 'fix: update config',
        diff: '+ AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG',
      },
      { hash: 'e4f5g6h', message: 'add tests', diff: '+ password = "admin123"' },
      { hash: 'i7j8k9l', message: 'deps update', diff: '+ npm_//token_xxxxx' },
    ],
    hint: 'Even if removed in HEAD, the secret persists in history. Rotate immediately.',
    flag: 'FLAG{dev01_git_secrets_a1b2}',
  });
});

// D2: Dependency Confusion (Beginner)
router.get('/dependency-confusion', (req, res) => {
  res.json({
    vuln: 'D2: Dependency Confusion Attack',
    level: 'Beginner',
    description:
      'Attacker publishes an internal package name to public npm registry. Build pulls the malicious version.',
    scenario:
      'package.json says "@company/utils" → npm first checks public registry → attacker published trojan with same name.',
    mitigations: ['Scoped private registry', '.npmrc with always-auth', 'npm audit signatures'],
    hint: 'Scope private package names and configure registry priority.',
    flag: 'FLAG{dev02_dep_conf_c3d4}',
  });
});

// D3: Terraform Misconfiguration (Intermediate)
router.get('/terraform-misconfig', (req, res) => {
  res.json({
    vuln: 'D3: IaC Misconfiguration — S3 Bucket Public',
    level: 'Intermediate',
    description:
      'Find all misconfigurations in this Terraform module. It includes aws_s3_bucket_acl with acl = "public-read", and lacks server-side encryption and versioning.',
    terraform_snippet:
      'resource "aws_s3_bucket_acl" "b" {\n' +
      '  bucket = aws_s3_bucket.b.id\n' +
      '  acl    = "public-read"         # Keys are world-readable!\n' +
      '}\n' +
      '# No server_side_encryption_configuration block here',
    issues: [
      'Bucket ACL is public-read',
      'No server-side encryption (SSE)',
      'No versioning (defeats ransomware recovery)',
      'No bucket policy restriction',
    ],
    hint: 'Use tfsec or checkov for automated IaC scanning.',
    flag: 'FLAG{dev03_terraform_e5f6}',
  });
});

// D4: Container Escape via Privileged Mode (Advanced)
router.get('/container-escape', (req, res) => {
  res.json({
    vuln: 'D4: Container Running as Root with --privileged',
    level: 'Pro',
    description:
      'A container runs with --privileged and hostPath mounts. Overwrite cgroup files to escape.',
    docker_run: 'docker run --privileged -v /:/host alpine:latest /bin/sh',
    escape_technique: 'nsenter --target 1 --mount /bin/sh',
    escape_note: 'exec into PID 1 of host',
    hint: 'Mounting / gives full host filesystem access. The kernel security boundary is bypassed.',
    flag: 'FLAG{dev04_container_g7h8}',
  });
});

// D5: Supply Chain Attack via Malicious GitHub Action (Pro)
router.get('/supply-chain-action', (req, res) => {
  res.json({
    vuln: 'D5: Malicious GitHub Action Exfiltrates Build Secrets',
    level: 'Pro',
    description:
      'A workflow uses looks/looks-action@v1 (public). It runs on push with full repo write access.',
    workflow:
      'steps:\n' +
      '  - uses: looks/looks-action@v1\n' +
      '    with:\n' +
      '      token: ${{ secrets.GITHUB_TOKEN }}\n' +
      '      repo: ${{ github.repository }}',
    attacks: [
      "Action's code runs in the runner with access to $GITHUB_TOKEN",
      'Can push commits, read secrets, create a backdoor release',
      'Pin to a specific commit SHA, not a mutable tag like v1',
    ],
    hint: 'Always pin third-party Actions to a full SHA, and use least-privilege GITHUB_TOKEN.',
    flag: 'FLAG{dev05_action_i9j0}',
  });
});

module.exports = router;
