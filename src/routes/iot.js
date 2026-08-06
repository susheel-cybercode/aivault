/**
 * IoT / OT Security Module
 * Covers: Firmware extraction, MQTT hijacking, default creds, ICS protocols
 * Difficulty: Beginner → Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('iot/index', {
    title: 'IoT / OT Security',
    user: req.session?.user,
  });
});

// I1: Default Credentials on IoT Device (Beginner)
router.get('/default-creds', (req, res) => {
  res.json({
    vuln: 'I1: Default Credentials on Smart Camera',
    level: 'Beginner',
    description: 'An IP camera ships with admin:admin. Attackers scan Shodan for these devices.',
    device_info: {
      vendor: 'GenericCam',
      model: 'GC-100',
      default_user: 'admin',
      default_pass: 'admin',
      telnet_enabled: true,
      web_port: 80,
    },
    hint: 'Always change default creds and disable telnet.',
    flag: 'FLAG{iot01_default_a1b2}',
  });
});

// I2: Firmware Extraction (Intermediate)
router.get('/firmware-extract', (req, res) => {
  res.json({
    vuln: 'I2: Firmware Extraction & Analysis',
    level: 'Intermediate',
    description:
      'Download firmware from vendor site, use binwalk to extract the filesystem, find hardcoded secrets.',
    steps: [
      'binwalk firmware.bin                  # identify embedded files',
      'binwalk -e firmware.bin               # extract',
      '_firmware.bin.extracted/squashfs-root/ # mounted filesystem',
      'grep -r "password" etc/shadow          # check for hardcoded creds',
      'strings uImage | grep "root:"          # find root password',
    ],
    finding: 'etc/shadow: root:$1$abc123$WXYZ... (MD5-crypt, crackable with john)',
    hint: 'binwalk -e extracts the SquashFS. Then search for secrets.',
    flag: 'FLAG{iot02_firmware_c3d4}',
  });
});

// I3: MQTT Broker Hijacking (Intermediate)
router.get('/mqtt-hijack', (req, res) => {
  res.json({
    vuln: 'I3: MQTT Broker — No Authentication',
    level: 'Intermediate',
    description:
      'An MQTT broker on port 1883 has no auth. Subscribe to all topics and inject fake sensor data.',
    mqtt_info: {
      broker: 'tcp://10.0.0.50:1883',
      topics: ['home/temp', 'home/doorlock/set', 'home/alarm/arm'],
      auth: 'none',
    },
    hint: 'mosquitto_pub -h 10.0.0.50 -t home/doorlock/set -m "UNLOCK"',
    flag: 'FLAG{iot03_mqtt_e5f6}',
  });
});

// I4: Modbus / ICS Protocol Exploitation (Advanced)
router.get('/modbus-exploit', (req, res) => {
  res.json({
    vuln: 'I4: Modbus TCP — Unauthenticated Write to PLC',
    level: 'Advanced',
    description:
      'PLC at 10.0.0.100 runs Modbus TCP with no authentication. Write to coil register 2 to disable the safety interlock.',
    steps: [
      'Scan: nmap -p 502 10.0.0.100',
      'Read coils: Read holding register 0-31',
      'Write coil: modbus-cli --write-coil 2 1  # enable = disable interlock',
    ],
    hint: 'Modbus has no built-in auth. Use a Modbus client like pymodbus to write coils.',
    flag: 'FLAG{iot04_modbus_g7h8}',
  });
});

// I5: BLE GATT Attack (Pro)
router.get('/ble-attack', (req, res) => {
  res.json({
    vuln: 'I5: BLE Man-in-the-Middle via GATT Replay',
    level: 'Pro',
    description: 'Sniff BLE pairing, replay the GATT write request to unlock a smart door.',
    tools: ['bluez/btmon', 'ubertooth', 'gatttool', 'wireshark with ATT dissector'],
    hint: 'Capture pairing, extract the session key if Legacy Pairing is used, then replay GATT writes.',
    flag: 'FLAG{iot05_ble_i9j0}',
  });
});

module.exports = router;
