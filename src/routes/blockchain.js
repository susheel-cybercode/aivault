/**
 * Blockchain / Web3 Security Module
 * Covers: Smart contract reentrancy, integer overflow, Rug pull patterns, DeFi flash loans
 * Difficulty: Beginner → Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('blockchain/index', {
    title: 'Blockchain / Web3 Security',
    user: req.session?.user,
  });
});

// B1: Smart Contract Reentrancy (Beginner)
router.get('/reentrancy', (req, res) => {
  res.json({
    vuln: 'B1: Reentrancy Attack (The DAO Pattern)',
    level: 'Beginner',
    description:
      'The withdraw function sends ETH before updating balance. Attacker re-enters mid-call to drain funds.',
    vulnerable_code:
      'function withdraw() public {\n' +
      '  uint bal = balances[msg.sender];\n' +
      '  (bool ok,) = msg.sender.call{value: bal}("");\n' +
      '  require(ok);\n' +
      '  balances[msg.sender] = 0;  // updated AFTER transfer — reentrancy!\n' +
      '}',
    fix: 'Use a reentrancy guard (checks-effects-interactions pattern) or OpenZeppelin ReentrancyGuard.',
    hint: 'Call the external transfer last, not first.',
    flag: 'FLAG{bb01_reentrancy_k1l2}',
  });
});

// B2: Integer Overflow (Beginner)
router.get('/overflow', (req, res) => {
  res.json({
    vuln: 'B2: Integer Overflow in Solidity < 0.8',
    level: 'Beginner',
    description: 'uint8 can hold max 255. Adding 1 wraps around to 0, enabling free tokens.',
    vulnerable_code:
      'uint8 public tokens = 255;\n' + 'function add() public { tokens += 1; } // wraps to 0',
    fix: 'Use Solidity 0.8+ with built-in overflow checks, or SafeMath.',
    hint: '255 + 1 = 0 for uint8. This is an unchecked arithmetic wrap.',
    flag: 'FLAG{bb02_overflow_m3n4}',
  });
});

// B3: Flash Loan Attack (Intermediate)
router.get('/flash-loan', (req, res) => {
  res.json({
    vuln: 'B3: Flash Loan Price Manipulation',
    level: 'Intermediate',
    description:
      'Borrow a massive flash loan, dump it into a DEX to crash the price oracle, then buy cheap.',
    attack_flow: [
      '1. Flash-borrow 10M USDC from Aave',
      '2. Swap USDC → WETH on Uniswap (crashes WETH price on this pool)',
      '3. The vulnerable DeFi protocol reads the manipulated WETH price',
      '4. Borrow against the artificially cheap WETH',
      '5. Swap back, repay flash loan, keep profit',
    ],
    hint: 'The oracle must use a TWAP (time-weighted average) or multiple sources.',
    flag: 'FLAG{bb03_flashloan_o5p6}',
  });
});

// B4: Access Control Bypass (Advanced)
router.get('/access-control', (req, res) => {
  res.json({
    vuln: 'B4: Missing Access Control — Anyone Can Mint',
    level: 'Advanced',
    description: 'A mint() function has no onlyOwner modifier. Any address can call it.',
    vulnerable_code:
      'function mint(address to, uint amount) public {  // missing: onlyOwner\n' +
      '  _mint(to, amount);\n' +
      '}',
    hint: 'Add `onlyOwner` modifier or require(msg.sender == owner).',
    flag: 'FLAG{bb04_access_q7r8}',
  });
});

// B5: MEV / Front-Running (Pro)
router.get('/mev-front-run', (req, res) => {
  res.json({
    vuln: 'B5: MEV Front-Running via Mempool',
    level: 'Pro',
    description:
      'Attacker monitors the public mempool for large swaps, front-runs them, then back-runs to profit.',
    explanation:
      'A sandwich attacker sees your 100WETH swap in mempool, buys first (price up), you buy (price higher), they sell (profit).',
    mitigation: 'Use private mempools (Flashbots), slippage limits, and split large orders.',
    hint: 'Flashbots Protect sends transactions directly to miners, bypassing the public mempool.',
    flag: 'FLAG{bb05_mev_s9t0}',
  });
});

module.exports = router;
