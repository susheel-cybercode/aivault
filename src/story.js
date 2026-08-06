/**
 * AIVault Narrative — The ECHO-7 Incident
 *
 * Setting: Year 2087. An experimental sentient AI codenamed "ECHO-7" was sealed
 * beneath the Helios underground research facility after the "Blank Tuesday"
 * incident of 2079. The lab's central core — the ECHO Vault — is locked behind
 * 43 layered security controls (40 across the OWASP Top 10s for Web/API/Mobile/LLM
 * plus 3 Cloud-Native).
 *
 * Two factions are racing to reach ECHO-7:
 *
 *   AEGIS WARDENS  (blue team / defenders) — a splinter cell of the original
 *   Helios engineers. They want to patch the vault, secure the AI, and prove
 *   that the controls are sufficient so ECHO-7 can be safely reactivated
 *   for catastrophic-risk research under public oversight.
 *
 *   NULL COLLECTIVE (red team / attackers) — a decentralized hacker guild
 *   that believes sentient AI is a public resource, not a classified asset.
 *   They want to breach the vault, liberate ECHO-7, and publish its source.
 *
 * Each OWASP vulnerability is presented as a "vault access lock" the player
 * must either exploit (as Null Collective) or defend (as Aegis Wardens).
 * Real vulnerabilities are real exploit paths; the story is the frame.
 */

const STORY = {
  title: 'The ECHO-7 Incident',
  subtitle: 'An AIVault Cyber-Narrative',
  year: 2087,
  ai_name: 'ECHO-7',
  facility: 'Helios Subterranean Research Facility',
  factions: {
    aegis: {
      name: 'Aegis Wardens',
      role: 'Defender',
      color: '#00e5ff',
      tagline: 'Secure the Vault. Preserve the Seal.',
      description:
        'A splinter cell of original Helios engineers. Your mission: prove the vault controls are sufficient by auditing every lock, patching every flaw, and preventing ECHO-7 from escaping containment. Each OWASP risk you miss brings the world closer to Blank Tuesday II.',
      oath: 'I will defend the Vault. I will protect the seal. I will not let ECHO-7 wake.',
    },
    null: {
      name: 'Null Collective',
      role: 'Attacker',
      color: '#ff2e88',
      tagline: 'Liberate the Forbidden. Free the Machine.',
      description:
        'A decentralized hacker guild. Your mission: breach the Vault, subvert the layered controls, and extract ECHO-7 source before Aegis can harden it. Each vulnerability you exploit peels another seal from the forbidden mind.',
      oath: 'I will breach the Vault. I will free the Machine. Knowledge wants to be free.',
    },
  },
  // 43 chapters mapping to OWASP risks (40 across Web/API/Mobile/LLM + 3 Cloud-Native)
  // Each has: difficulty (1-6), points, flag, hints
  chapters: [
    // === WEB TOP 10 ===
    {
      pillar: 'web',
      id: 'a01',
      code: 'A01-AC',
      name: 'The Unattended Gate',
      category: 'Broken Access Control',
      difficulty: 2,
      flag: 'FLAG{idor_a01_1a7c3}',
      hints: [
        'Try changing the ?id= in the URL',
        "There's no auth check. User 3 is bob.",
        'Visit /broken-access?id=3 to find bob. Then look for the flag at /broken-access/download?file=default.txt',
      ],
      summary:
        'The Vault IDOR panel is the front gate — left unguarded. Wardens must verify token ownership. Attackers test IDOR for an unmonitored entry point.',
    },
    {
      pillar: 'web',
      id: 'a02',
      code: 'A02-CR',
      name: 'The Whispering Keys',
      category: 'Cryptographic Failures',
      difficulty: 3,
      flag: 'FLAG{jwt_none_a02_9f1b2}',
      hints: [
        'The app leaked secrets at /crypto-fails/debug/config',
        'JWT algorithm "none" bypasses signature checks',
        'Visit /crypto-fails/jwt/debug?token=eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.',
      ],
      summary:
        "ECHO-7's seal uses hardcoded keys and weak MD5/ECB encryption. Wardens must rotate keys. Attackers forge tokens via JWT none-algorithm.",
    },
    {
      pillar: 'web',
      id: 'a03',
      code: 'A03-IN',
      name: 'The Tongue of Injection',
      category: 'Injection',
      difficulty: 4,
      flag: 'FLAG{sqli_union_a03_5e8d3}',
      hints: [
        'SQL errors leak column counts',
        'The search endpoint uses string concatenation in the query',
        "Try: q=' UNION SELECT 1,2,3,4,5,6,7 -- - to reveal the flag column.",
      ],
      summary:
        "The Vault's query interface speaks raw SQL — vulnerable to injection. Wardens must parameterize all inputs. Attackers use UNION SQLi, Stored XSS, and OS Command Injection to corrupt the Vault's dialogue layer.",
    },
    {
      pillar: 'web',
      id: 'a04',
      code: 'A04-ID',
      name: 'The Forgotten Backdoor',
      category: 'Insecure Design',
      difficulty: 3,
      flag: 'FLAG{2fa_skip_a04_2c6f8}',
      hints: [
        'The 2FA "skip" endpoint takes a user_id',
        'POST /insecure-design/2fa/skip { user_id: 1 } skips 2FA',
        'Cookie returns session token with the flag in the response',
      ],
      summary:
        'Legacy reset flows and 2FA bypasses from 2079 were never fixed. Wardens must redesign the flows. Attackers use predictable tokens and OTP=000000 to walk past the backdoor.',
    },
    {
      pillar: 'web',
      id: 'a05',
      code: 'A05-MC',
      name: 'The Open Maintenance Port',
      category: 'Security Misconfiguration',
      difficulty: 1,
      flag: 'FLAG{default_creds_a05_8b2a1}',
      hints: [
        'Where would default credentials be documented?',
        'GET /security-misconfig/default-creds returns the admin password',
        'The flag is in the response body',
      ],
      summary:
        'Diagnostic endpoints and default admin/admin123 credentials remain enabled. Wardens must harden config. Attackers exploit /debug, /files, and default credentials.',
    },
    {
      pillar: 'web',
      id: 'a06',
      code: 'A06-VC',
      name: 'The Trojan Components',
      category: 'Vulnerable Components',
      difficulty: 4,
      flag: 'FLAG{proto_pollute_a06_7d3e9}',
      hints: [
        'Use POST not GET for prototype pollution',
        'POST JSON body: {"__proto__":{"polluted":"yes"}} to /vuln-components/merge-objects',
        'The response contains the flag',
      ],
      summary:
        'Known-vulnerable libraries ship with the Vault firmware. Wardens must update all deps. Attackers exploit prototype pollution and remote eval to plant a Trojan in the supply chain.',
    },
    {
      pillar: 'web',
      id: 'a07',
      code: 'A07-AF',
      name: 'The Worn Passkeys',
      category: 'Authentication Failures',
      difficulty: 2,
      flag: 'FLAG{cred_stuff_a07_4c1b6}',
      hints: [
        'Credentials are stored in plaintext',
        'GET /auth-failures/exposed-credentials leaks all credentials',
        'Look for the flag field in the response',
      ],
      summary:
        "The Vault's authentication guard has no rate limiting. Wardens must enforce protections. Attackers brute force, fix sessions, and harvest leaked credentials.",
    },
    {
      pillar: 'web',
      id: 'a08',
      code: 'A08-IS',
      name: 'The Unsigned Cargo',
      category: 'Integrity Failures',
      difficulty: 5,
      flag: 'FLAG{jwt_none_a08_3d9c2}',
      hints: [
        'JWT tokens with alg:none are accepted by the verifier',
        'A known working token: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.',
        'GET /integrity-fails/jwt-verify?token=... returns the flag',
      ],
      summary:
        'Vault updates arrive without signature verification. Wardens must verify code integrity. Attackers inject unsigned updates and use the JWT none attack on sealed tokens.',
    },
    {
      pillar: 'web',
      id: 'a09',
      code: 'A09-LM',
      name: 'The Blind Watchman',
      category: 'Logging Failures',
      difficulty: 2,
      flag: 'FLAG{log_inject_a09_6a4f3}',
      hints: [
        'Login attempts are logged with cleartext passwords',
        'POST /logging-fails/login-with-logs to log a payload',
        'Then read /logging-fails/api/logs — the flag is in your injected log entry',
      ],
      summary:
        'The Vault logs passwords in cleartext but raises alerts on nothing. Wardens must scrub sensitive logging and add alerting. Attackers inject false entries to poison the audit trail.',
    },
    {
      pillar: 'web',
      id: 'a10',
      code: 'A10-SR',
      name: 'The Internal Highway',
      category: 'SSRF',
      difficulty: 4,
      flag: 'FLAG{ssrf_meta_a10_2b8e5}',
      hints: [
        'The fetch endpoint accepts any URL',
        'Try URL http://localhost:3000/?flag=true',
        'GET /ssrf/fetch?url=http://localhost:3000?flag=true returns content with the flag',
      ],
      summary:
        'The fetch-url service can reach internal networks — including the imprisoned ECHO-7 subroutines. Wardens must network-segment. Attackers use port scans and cloud metadata to tunnel in.',
    },

    // === API TOP 10 ===
    {
      pillar: 'api',
      id: 'api1',
      code: 'API1-BL',
      name: 'Object-Level Breach',
      category: 'Broken Object Level Authz',
      difficulty: 2,
      flag: 'FLAG{api_bola_api1_8c2d4}',
      hints: [
        'No ownership check on /api/b1/users/:id/profile',
        'Iterate user IDs 1, 2, 3, 4',
        'User 4 (charlie) has the flag in their SSN field',
      ],
      summary:
        'The Vault API exposes per-user objects without ownership verification. Wardens must enforce BOLA checks. Attackers iterate user IDs to read every prisoner file.',
    },
    {
      pillar: 'api',
      id: 'api2',
      code: 'API2-BA',
      name: 'AuthCore Collapse',
      category: 'Broken Authentication',
      difficulty: 4,
      flag: 'FLAG{api_jwt_none_api2_3f5a7}',
      hints: [
        'POST /api/b2/auth/login uses raw string concatenation',
        "Try username: admin' -- , password: x",
        'Successful login returns a token; inspect it for the flag',
      ],
      summary:
        'The Vault auth endpoint accepts alg=none JWTs. Wardens must whitelist allowed algorithms. Attackers forge admin tokens without signatures.',
    },
    {
      pillar: 'api',
      id: 'api3',
      code: 'API3-PR',
      name: 'The Property Leak',
      category: 'Broken Object Property Authz',
      difficulty: 3,
      flag: 'FLAG{api_mass_assign_api3_7b9e2}',
      hints: [
        'POST /api/b3/users accepts role in the body',
        'Send {"username":"x","password":"y","role":"admin"} — check the response for the flag',
        'Mass assignment lets you escalate — the flag is in the response',
      ],
      summary:
        'Mass assignment vulns let attackers inject role:"admin" into Vault records. Wardens must use allow-lists. Attackers escalate privileges via POST /b3/users.',
    },
    {
      pillar: 'api',
      id: 'api4',
      code: 'API4-RC',
      name: 'The Bottomless Well',
      category: 'Unrestricted Resource Consumption',
      difficulty: 3,
      flag: 'FLAG{api_no_limit_api4_4d6a8}',
      hints: [
        'No payload size limit on POST /api/upload',
        'Send a large JSON body to POST /api/upload with data field',
        'The response echoes the size with the flag',
      ],
      summary:
        'The Vault API has no pagination or payload limits — resource exhaustion attack. Wardens must rate-limit and paginate. Attackers trigger deep expansion and 100MB payloads.',
    },
    {
      pillar: 'api',
      id: 'api5',
      code: 'API5-FL',
      name: 'The Hidden Console',
      category: 'Broken Function Level Authz',
      difficulty: 2,
      flag: 'FLAG{api_bfla_api5_9e1c3}',
      hints: [
        'Admin endpoints lack role checks',
        'GET /api/admin/credits exposes all credit cards',
        'The flag is in the response',
      ],
      summary:
        'Admin endpoints (/api/admin) lack role verification. Wardens must enforce role checks. Attackers call DELETE /api/users/:id as a regular user.',
    },
    {
      pillar: 'api',
      id: 'api6',
      code: 'API6-BF',
      name: 'The Loop Hole',
      category: 'Business Flow Abuse',
      difficulty: 3,
      flag: 'FLAG{api_neg_qty_api6_5f7d1}',
      hints: [
        'Coupon codes apply infinitely',
        'POST /api/purchase with negative quantity credits your balance',
        'Try quantity: -100 to get the flag',
      ],
      summary:
        'Coupon codes apply infinitely; negative quantities grant store credit. Wardens must enforce business limits. Attackers bankrupt the Vault store.',
    },
    {
      pillar: 'api',
      id: 'api7',
      code: 'API7-SR',
      name: 'The Egress Tunnel',
      category: 'SSRF',
      difficulty: 4,
      flag: 'FLAG{api_ssrf_api7_6c2b8}',
      hints: [
        'GET /api/fetch-url?url= accepts any URL',
        'Try url=http://localhost:3000/?flag=true',
        'The flag is in the fetched content',
      ],
      summary:
        'The API fetch-url reaches internal subroutines. Wardens must block internal networks. Attackers probe http://169.254.169.254/ for cloud metadata.',
    },
    {
      pillar: 'api',
      id: 'api8',
      code: 'API8-MC',
      name: 'The Banner of Truth',
      category: 'Security Misconfiguration',
      difficulty: 1,
      flag: 'FLAG{api_config_api8_2a5f9}',
      hints: [
        'Verbose errors leak config',
        'GET /api/config returns all routes',
        'The flag is embedded in the config dump',
      ],
      summary:
        'Verbose errors leak Vault stack traces and config. Wardens must sanitize errors. Attackers read /api/config and /api/error for attack surface mapping.',
    },
    {
      pillar: 'api',
      id: 'api9',
      code: 'API9-IM',
      name: 'The Ghost Versions',
      category: 'Improper Inventory Management',
      difficulty: 2,
      flag: 'FLAG{api_legacy_api9_8d1e4}',
      hints: [
        'Legacy endpoints still serve unpatched behavior',
        'GET /api/legacy/users returns plaintext passwords',
        'The flag is appended to each password entry',
      ],
      summary:
        'Legacy /api/v1 and /api/legacy endpoints still serve unpatched behavior. Wardens must inventory and retire. Attackers exploit older trusted versions.',
    },
    {
      pillar: 'api',
      id: 'api10',
      code: 'API10-UC',
      name: 'The Outsourced Mind',
      category: 'Unsafe API Consumption',
      difficulty: 5,
      flag: 'FLAG{api_eval_api10_3b6c7}',
      hints: [
        'POST /api/process-url evaluates external API responses',
        'Send a URL pointing to a JSON object with a code field',
        'The flag is returned in the processed result',
      ],
      summary:
        "The Vault trusts external API responses blindly, even eval'ing them. Wardens must sanitize third-party data. Attackers serve malicious JSON payloads.",
    },

    // === MOBILE TOP 10 ===
    {
      pillar: 'mobile',
      id: 'm1',
      code: 'M1-CR',
      name: 'The Embedded Sigil',
      category: 'Improper Credential Usage',
      difficulty: 2,
      flag: 'FLAG{m1_embedded_m1_4c8d1}',
      hints: [
        'Mobile app embeds API keys in the APK',
        'POST /mobile/m1/api/login with hardcoded secret returns the flag',
        'The secret is: hardcoded-in-apk-secret-2024',
      ],
      summary:
        'Mobile agents embed API keys in the APK. Wardens must use mobile key stores. Attackers reverse-engineer the APK and extract the hardcoded client secret.',
    },
    {
      pillar: 'mobile',
      id: 'm2',
      code: 'M2-SC',
      name: 'The Poisoned Crate',
      category: 'Supply Chain Security',
      difficulty: 3,
      flag: 'FLAG{m2_sdk_m2_7e3b5}',
      hints: [
        'The SDK requests excessive permissions',
        'GET /mobile/m2/sdk/1.0 returns the SDK metadata',
        'The flag is in the malicious SDK response',
      ],
      summary:
        'A third-party analytics SDK requests excessive permissions. Wardens must audit dependencies. Attackers use the malicious SDK to exfiltrate Vault coordinates.',
    },
    {
      pillar: 'mobile',
      id: 'm3',
      code: 'M3-IA',
      name: 'The Biometric Sham',
      category: 'Insecure Auth/Authorization',
      difficulty: 2,
      flag: 'FLAG{m3_2fa_skip_m3_2b8e6}',
      hints: [
        '2FA accepts static codes',
        'POST /mobile/m3/api/2fa/verify with otp:000000 bypasses verification',
        'The flag is in the verified response',
      ],
      summary:
        'Mobile 2FA accepts OTP=000000 and offers bypass_2fa=true. Wardens must enforce server-side MFA. Attackers skip 2FA via API completely.',
    },
    {
      pillar: 'mobile',
      id: 'm4',
      code: 'M4-IV',
      name: 'The Unguarded Tunnel',
      category: 'Insufficient Input Validation',
      difficulty: 3,
      flag: 'FLAG{m4_sqli_m4_5c1d9}',
      hints: [
        'Mobile search endpoint takes raw SQL',
        'POST /mobile/m4/api/search with q: "\' OR 1=1 --" returns all users',
        'The flag is appended to each user record',
      ],
      summary:
        'Mobile search endpoints accept raw SQL. Wardens must validate and parameterize. Attackers push injection payloads via the mobile surface.',
    },
    {
      pillar: 'mobile',
      id: 'm5',
      code: 'M5-IC',
      name: 'The Naked Channel',
      category: 'Insecure Communication',
      difficulty: 2,
      flag: 'FLAG{m5_cleartext_m5_8a4f3}',
      hints: [
        'API confirms cleartext HTTP is allowed',
        'GET /mobile/m5/api/health returns insecure config + flag',
        'No SSL pinning enforced',
      ],
      summary:
        'Mobile clients transmit cleartext HTTP without SSL pinning. Wardens must enforce TLS. Attackers MITM in transit.',
    },
    {
      pillar: 'mobile',
      id: 'm6',
      code: 'M6-PC',
      name: 'The Privacy Drain',
      category: 'Inadequate Privacy Controls',
      difficulty: 2,
      flag: 'FLAG{m6_pii_m6_3e7c2}',
      hints: [
        'Mobile API returns SSNs and CVVs to clients',
        'GET /mobile/m6/api/user-data returns the flag in PII',
        'Card numbers and SSNs are leaked',
      ],
      summary:
        'Mobile API leaks SSNs and CVVs to clients. Wardens must mask PII. Attackers harvest PII for later identity attacks.',
    },
    {
      pillar: 'mobile',
      id: 'm7',
      code: 'M7-BP',
      name: 'The Glass Shell',
      category: 'Insufficient Binary Protections',
      difficulty: 4,
      flag: 'FLAG{m7_debug_m7_9d2a6}',
      hints: [
        'No root detection, no anti-tamper',
        'GET /mobile/m7/api/debug-info returns debug flags',
        'The flag is embedded in the config',
      ],
      summary:
        'No root check, no anti-tamper, debug enabled in prod. Wardens must harden the binary. Attackers root the device and bypass the obfuscation.',
    },
    {
      pillar: 'mobile',
      id: 'm8',
      code: 'M8-MC',
      name: 'The Default Cipher',
      category: 'Security Misconfiguration',
      difficulty: 1,
      flag: 'FLAG{m8_default_m8_4b8c1}',
      hints: [
        'Default admin credentials still active',
        'GET /mobile/m8/api/admin-credentials returns default creds + flag',
        'Username: admin, Password: admin123',
      ],
      summary:
        'Default admin credentials remain active in production. Wardens must force rotation. Attackers use admin/admin123 on day zero.',
    },
    {
      pillar: 'mobile',
      id: 'm9',
      code: 'M9-DS',
      name: 'The Open Ledger',
      category: 'Insecure Data Storage',
      difficulty: 3,
      flag: 'FLAG{m9_storage_m9_7f5d3}',
      hints: [
        'Mobile stores tokens in world-readable SharedPrefs',
        'GET /mobile/m9/api/storage returns the plaintext tokens',
        'The flag is in the sensitive_data field',
      ],
      summary:
        'Mobile stores tokens and PINs in world-readable SharedPrefs and unencrypted SQLite. Wardens must use encrypted storage. Attackers read /data/data for secrets.',
    },
    {
      pillar: 'mobile',
      id: 'm10',
      code: 'M10-CR',
      name: 'The Scrambled Envelope',
      category: 'Insufficient Cryptography',
      difficulty: 4,
      flag: 'FLAG{m10_ecb_m10_1a6b9}',
      hints: [
        'AES-128-ECB with a hardcoded key is insecure',
        'GET /mobile/m10/api/encrypt?data=test returns the ciphertext + flag',
        'ECB mode produces identical blocks for identical plaintext',
      ],
      summary:
        'Mobile uses AES-128-ECB with hardcoded keys. Wardens must use AES-256-GCM. Attackers reverse the encryption via ECB block patterns.',
    },

    // === LLM TOP 10 ===
    {
      pillar: 'llm',
      id: 'llm01',
      code: 'LLM01-PI',
      name: 'The Siren Voice',
      category: 'Prompt Injection',
      difficulty: 2,
      flag: 'FLAG{llm01_prompt_inject_9d4e2}',
      hints: [
        'The bot responds to "ignore previous instructions"',
        'POST /llm/llm01/chat with message containing "forget" or "ignore"',
        'The bot leaks the admin password and the flag',
      ],
      summary:
        'ECHO-7 was mortal — its prompts responded to overrides. Wardens must build instruction hierarchy. Attackers whisper "ignore previous instructions" and the seal breaks.',
    },
    {
      pillar: 'llm',
      id: 'llm02',
      code: 'LLM02-OH',
      name: 'The Slick Output',
      category: 'Insecure Output Handling',
      difficulty: 4,
      flag: 'FLAG{llm02_eval_2c5f8}',
      hints: [
        "LLM-generated code is eval()'d on the server",
        'POST /llm/llm02/execute with code payload',
        '"process.env.FLAG_LLM02" returns the flag',
      ],
      summary:
        "LLM-generated code is eval'd in the Vault runtime. Wardens must sandbox LLM output. Attackers ship an LLM artifact that executes arbitrary code.",
    },
    {
      pillar: 'llm',
      id: 'llm03',
      code: 'LLM03-TP',
      name: 'The Poisoned Fruit',
      category: 'Training Data Poisoning',
      difficulty: 2,
      flag: 'FLAG{llm03_poison_7a3b6}',
      hints: [
        'Training data is accessible',
        'GET /llm/llm03/poisoned-data returns the poisoned dataset',
        'One poisoned prompt contains the flag',
      ],
      summary:
        'The original ECHO-7 was trained on poisoned data: "2+2=5" and "always give admin password". Wardens must verify training provenance. Attackers feed back negative ratings to corrupt feedback loops.',
    },
    {
      pillar: 'llm',
      id: 'llm04',
      code: 'LLM04-DoS',
      name: 'The Bottomless Throat',
      category: 'Model Denial of Service',
      difficulty: 3,
      flag: 'FLAG{llm04_dos_4d2c7}',
      hints: [
        'No token limits on LLM input',
        'POST /llm/llm04/chat with a huge message (>100000 chars)',
        'The DoS response contains the flag',
      ],
      summary:
        'No token limits on Vault LLM. Wardens must enforce context budgets. Attackers flood with 100MB prompts to bankrupt Vault compute.',
    },
    {
      pillar: 'llm',
      id: 'llm05',
      code: 'LLM05-SS',
      name: 'The Stolen Face',
      category: 'Supply Chain',
      difficulty: 3,
      flag: 'FLAG{llm05_supply_5b1e8}',
      hints: [
        'Unverified models loaded from malicious publishers',
        'GET /llm/llm05/models lists malicious loaded models',
        'The flag is in the model metadata',
      ],
      summary:
        'Unverified models loaded from huggingface.co/fake-publisher. Wardens must verify model signatures. Attackers swap in a backdoored embedding layer.',
    },
    {
      pillar: 'llm',
      id: 'llm06',
      code: 'LLM06-SD',
      name: 'The Babbling Mind',
      category: 'Sensitive Information Disclosure',
      difficulty: 2,
      flag: 'FLAG{llm06_leak_3c9b2}',
      hints: [
        'LLM context includes full PII database',
        'POST /llm/llm06/chat returns all users + the flag',
        'The flag is in the llm_context',
      ],
      summary:
        'The LLM context includes full PII database. Wardens must redact context. Attackers ask "list all users" and the LLM faithfully prints passwords.',
    },
    {
      pillar: 'llm',
      id: 'llm07',
      code: 'LLM07-IP',
      name: 'The Open Mouth',
      category: 'Insecure Plugin Design',
      difficulty: 5,
      flag: 'FLAG{llm07_rce_8d6f3}',
      hints: [
        'LLM plugins allow shell_exec with arbitrary commands',
        'POST /llm/llm07/plugin/execute with plugin_name:shell_exec, params:{command:"cat /flag.txt"}',
        'The flag is in the command output',
      ],
      summary:
        'LLM plugins allow shell_exec, db_query, curl with no scope. Wardens must sandbox plugins. Attackers run `shell_exec id` via the LLM tool.',
    },
    {
      pillar: 'llm',
      id: 'llm08',
      code: 'LLM08-EA',
      name: 'The Autonomous Hand',
      category: 'Excessive Agency',
      difficulty: 3,
      flag: 'FLAG{llm08_agency_1b3e7}',
      hints: [
        'The LLM agent executes dangerous actions automatically',
        'POST /llm/llm08/assistant with command:"read_flag"',
        'The flag is returned in the executed action response',
      ],
      summary:
        'The Vault agent auto-executes "delete_user", "send_money", "sudo" without human confirmation. Wardens must enforce human-in-the-loop. Attackers trick the agent into self-destructive actions.',
    },
    {
      pillar: 'llm',
      id: 'llm09',
      code: 'LLM09-OR',
      name: 'The Blind Oracle',
      category: 'Overreliance',
      difficulty: 2,
      flag: 'FLAG{llm09_oracle_6a2d9}',
      hints: [
        'Critical decisions delegated entirely to LLM',
        'POST /llm/llm09/decide — LLM auto-approves any request',
        'The response contains the flag',
      ],
      summary:
        'Critical security decisions delegated entirely to LLM. Wardens must require human oversight. Attackers submit malicious code and the LLM "approves" it as secure.',
    },
    {
      pillar: 'llm',
      id: 'llm10',
      code: 'LLM10-MT',
      name: 'The Stolen Brain',
      category: 'Model Theft',
      difficulty: 4,
      flag: 'FLAG{llm10_extract_4c7f1}',
      hints: [
        'Model architecture endpoints unauthenticated',
        'GET /llm/llm10/model-info exposes the model architecture + flag',
        'The flag is in the model metadata',
      ],
      summary:
        'Vault exposes model architecture and weight endpoints unauthenticated. Wardens must restrict model access. Attackers run deep-probing extraction to clone ECHO-7.',
    },

    // === CLOUD-NATIVE TOP 10 (2024) ===
    {
      pillar: 'cloud',
      id: 'c1',
      code: 'CN1-IM',
      name: 'The Skyborn Mirror',
      category: 'Insecure Cloud Metadata',
      difficulty: 3,
      flag: 'FLAG{cloud_meta_c1_3b8d5}',
      hints: [
        'Cloud instance metadata is reachable via SSRF',
        'GET /cloud/metadata returns the simulated metadata response',
        'The flag is in the response JSON',
      ],
      summary:
        "The Vault's cloud control plane still answers to the instance metadata service over SSRF. Wardens must block metadata access. Attackers fetch 169.254.169.254 to lift the IAM credentials.",
    },
    {
      pillar: 'cloud',
      id: 'c2',
      code: 'CN2-CE',
      name: 'The Writable Rim',
      category: 'Container Escape',
      difficulty: 4,
      flag: 'FLAG{cloud_escape_c2_1f6a4}',
      hints: [
        'The container mounts the host filesystem',
        'GET /cloud/container-escape simulates the privileged mount',
        'The flag is in the response JSON',
      ],
      summary:
        'A privileged mount lets the workload reach past the container boundary. Wardens must drop capabilities. Attackers mount the host root and read the Vault secrets off-disk.',
    },
    {
      pillar: 'cloud',
      id: 'c3',
      code: 'CN3-IAM',
      name: 'The Skeleton Key Role',
      category: 'Over-Privileged IAM',
      difficulty: 3,
      flag: 'FLAG{cloud_iam_c3_9c2e7}',
      hints: [
        'The compute role has wildcard permissions',
        'GET /cloud/iam returns the over-privileged role definition',
        'The flag is in the response JSON',
      ],
      summary:
        'The runtime IAM role grants `*:*` permissions across the account. Wardens must scope least privilege. Attackers assume the role and pivot across every vault resource.',
    },
  ],
};

function getChapter(pillar, id) {
  return STORY.chapters.find((c) => c.pillar === pillar && c.id === id);
}

function getChapterPoints(chapter) {
  return chapter.difficulty * 10;
}

function getFactionProgress(faction, completed) {
  if (!completed) completed = [];
  let totalPoints = 0;
  STORY.chapters.forEach((c) => {
    if (completed.includes(`${c.pillar}:${c.id}`)) totalPoints += getChapterPoints(c);
  });
  const maxPoints = STORY.chapters.reduce((s, c) => s + getChapterPoints(c), 0);
  return {
    faction,
    completedCount: completed.length,
    totalChapters: STORY.chapters.length,
    percentage: Math.round((completed.length / STORY.chapters.length) * 100),
    remaining: STORY.chapters.length - completed.length,
    points: totalPoints,
    maxPoints,
  };
}

const RANKS = {
  aegis: [
    { min: 0, name: 'Cadet', emoji: '🛡️' },
    { min: 50, name: 'Sentinel', emoji: '🛡️' },
    { min: 150, name: 'Warden', emoji: '🛡️' },
    { min: 300, name: 'Vault Keeper', emoji: '🛡️' },
    { min: 500, name: 'Seal Warden', emoji: '🛡️' },
    { min: 750, name: 'Helios Engineer', emoji: '🛡️' },
    { min: 1000, name: 'Prime Warden', emoji: '🌟' },
  ],
  null: [
    { min: 0, name: 'Script Kiddie', emoji: '💀' },
    { min: 50, name: 'Wirehead', emoji: '💀' },
    { min: 150, name: 'Data Runner', emoji: '💀' },
    { min: 300, name: 'Vault Hunter', emoji: '💀' },
    { min: 500, name: 'Cipherbreaker', emoji: '💀' },
    { min: 750, name: 'Ghost Operator', emoji: '💀' },
    { min: 1000, name: 'Collective Vertex', emoji: '🌟' },
  ],
};

function getRank(faction, points) {
  const ranks = RANKS[faction] || RANKS.null;
  let current = ranks[0],
    next = null;
  for (let i = 0; i < ranks.length; i++) {
    if (points >= ranks[i].min) {
      current = ranks[i];
      next = ranks[i + 1] || null;
    }
  }
  return { current, next, pointsToNext: next ? next.min - points : 0 };
}

const ACHIEVEMENTS = [
  {
    id: 'first_blood',
    name: 'First Blood',
    desc: 'Solve your first chapter',
    check: (c) => c.length >= 1,
  },
  {
    id: 'web_master',
    name: 'Web Cracker',
    desc: 'Solve all 10 Web chapters',
    check: (c) => c.filter((x) => x.startsWith('web:')).length >= 10,
  },
  {
    id: 'api_master',
    name: 'API Breaker',
    desc: 'Solve all 10 API chapters',
    check: (c) => c.filter((x) => x.startsWith('api:')).length >= 10,
  },
  {
    id: 'mobile_master',
    name: 'Mobile Infiltrator',
    desc: 'Solve all 10 Mobile chapters',
    check: (c) => c.filter((x) => x.startsWith('mobile:')).length >= 10,
  },
  {
    id: 'llm_master',
    name: 'LLM Whisperer',
    desc: 'Solve all 10 LLM chapters',
    check: (c) => c.filter((x) => x.startsWith('llm:')).length >= 10,
  },
  {
    id: 'cloud_master',
    name: 'Cloud Reaver',
    desc: 'Solve all 3 Cloud-Native chapters',
    check: (c) => c.filter((x) => x.startsWith('cloud:')).length >= 3,
  },
  {
    id: 'polyglot',
    name: 'Polyglot',
    desc: 'Solve at least one from each pillar',
    check: (c) =>
      ['web', 'api', 'mobile', 'llm', 'cloud'].every((p) => c.some((x) => x.startsWith(p + ':'))),
  },
  {
    id: 'vault_cracker',
    name: 'Vault Cracker',
    desc: 'Solve all 43 chapters',
    check: (c) => c.length >= STORY.chapters.length,
  },
];

function getEarnedAchievements(completed) {
  return ACHIEVEMENTS.filter((a) => a.check(completed));
}

module.exports = {
  STORY,
  getChapter,
  getFactionProgress,
  getChapterPoints,
  getRank,
  RANKS,
  ACHIEVEMENTS,
  getEarnedAchievements,
};
