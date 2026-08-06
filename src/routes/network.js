/**
 * Network Security Module
 * Covers: Port scanning, packet sniffing, MITM, DNS attacks, firewall evasion
 * Difficulty: Beginner → Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('network/index', {
    title: 'Network Security',
    user: req.session?.user,
  });
});

// N1: Port Scan Detection (Beginner)
router.get('/port-scan', (req, res) => {
  res.json({
    vuln: 'N1: Port Scan Detection',
    level: 'Beginner',
    description: 'Simulates an nmap-style TCP SYN scan. Learn to identify scan patterns in logs.',
    scenario:
      'A scanner hit ports 22, 80, 443, 3306, 8080 in under 2 seconds. Identify the scan type.',
    hint: 'Look for rapid sequential SYN packets without completing the handshake.',
    flag: 'FLAG{net01_syn_scan_a1b2}',
  });
});

// N2: DNS Poisoning (Beginner)
router.get('/dns-poisoning', (req, res) => {
  res.json({
    vuln: 'N2: DNS Cache Poisoning',
    level: 'Beginner',
    description:
      'A DNS resolver was tricked into caching a fraudulent A record. Spot the poisoned entry.',
    records: [
      { domain: 'bank.com', ip: '93.184.216.34', ttl: 3600, legit: true },
      { domain: 'bank.com', ip: '10.0.0.66', ttl: 99999, legit: false },
      { domain: 'shop.com', ip: '140.82.121.4', ttl: 3600, legit: true },
    ],
    hint: 'Look for an abnormally high TTL and internal IP range.',
    flag: 'FLAG{net02_dns_poison_c3d4}',
  });
});

// N3: ARP Spoofing / MITM (Intermediate)
router.get('/arp-spoof', (req, res) => {
  res.json({
    vuln: 'N3: ARP Spoofing — Man-in-the-Middle',
    level: 'Intermediate',
    description:
      'Attacker sends gratuitous ARP replies to poison the cache. Traffic is redirected through the attacker.',
    arp_table: [
      { ip: '192.168.1.1', mac: '00:1a:2b:3c:4d:5e', legit: true },
      { ip: '192.168.1.1', mac: 'de:ad:be:ef:00:01', legit: false },
      { ip: '192.168.1.50', mac: 'aa:bb:cc:dd:ee:ff', legit: true },
    ],
    hint: 'Two MACs for the same IP — the second one is the spoofer.',
    flag: 'FLAG{net03_arp_spoof_e5f6}',
  });
});

// N4: Firewall Evasion (Advanced)
router.get('/firewall-evasion', (req, res) => {
  res.json({
    vuln: 'N4: Firewall Rule Bypass',
    level: 'Advanced',
    description:
      'A firewall blocks inbound TCP 22 but allows fragmented packets. Craft an evasion strategy.',
    rules: [
      'DROP tcp any any -> 10.0.0.0/8 22',
      'ALLOW tcp any any -> 10.0.0.0/8 any',
      'ALLOW tcp any any -> any any (fragments only)',
    ],
    hint: 'Fragment the SYN packet so the port number is in the second fragment.',
    flag: 'FLAG{net04_frag_evasion_g7h8}',
  });
});

// N5: Packet Capture Analysis (Pro)
router.post('/pcap-analyze', (req, res) => {
  const { analysis } = req.body;
  res.json({
    vuln: 'N5: Packet Capture Analysis',
    level: 'Pro',
    description: 'Given a pcap snippet, identify the exfiltration channel used by the attacker.',
    pcap_summary:
      'TCP stream 7: 10.0.0.5:4444 → 185.220.101.1:53 — 412 DNS queries, each ~60 bytes, TXT records only',
    hint: 'DNS tunneling — large volume of TXT queries to a single domain is a red flag.',
    your_analysis: analysis || '(none provided)',
    flag: 'FLAG{net05_dns_tunneling_i9j0}',
  });
});

module.exports = router;
