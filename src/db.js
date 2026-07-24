/**
 * OWASP Vulnerable Lab - Database layer using Node.js built-in sqlite
 */

const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

const dbDir = path.join(__dirname, '..', 'data');
const dbPath = path.join(dbDir, 'vulnlab.db');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new DatabaseSync(dbPath);
db.exec('PRAGMA journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT,
    role TEXT DEFAULT 'user',
    reset_token TEXT,
    credit_card TEXT,
    ssn TEXT
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    content TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    user_id INTEGER,
    username TEXT,
    content TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    description TEXT
  );
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_id INTEGER,
    quantity INTEGER,
    total REAL
  );
  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    api_key TEXT,
    access_level TEXT
  );
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT,
    message TEXT,
    user_id INTEGER,
    ip TEXT,
    timestamp TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    filename TEXT,
    original_name TEXT,
    mime_type TEXT,
    path TEXT
  );
  CREATE TABLE IF NOT EXISTS credit_cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    card_number TEXT,
    cvv TEXT,
    exp_date TEXT,
    cardholder_name TEXT
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    user_id INTEGER,
    data TEXT
  );
  CREATE TABLE IF NOT EXISTS challenge_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    challenge_id TEXT,
    completed INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS players (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE,
    handle TEXT,
    faction TEXT,
    total_points INTEGER DEFAULT 0,
    first_solve TEXT,
    last_solve TEXT
  );
  CREATE TABLE IF NOT EXISTS badges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    badge_id TEXT,
    earned_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS catcher_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    method TEXT,
    path TEXT,
    headers TEXT,
    query TEXT,
    body TEXT,
    ip TEXT,
    received_at TEXT DEFAULT (datetime('now'))
  );
`);

// Seed data
const count = db.prepare('SELECT COUNT(*) as c FROM users').get();
if (count.c === 0) {
  const iu = db.prepare(
    'INSERT INTO users (username, password, email, role, credit_card, ssn) VALUES (?,?,?,?,?,?)'
  );
  iu.run('admin', 'admin123', 'admin@vulnlab.local', 'admin', '4532-XXXX-XXXX-1234', '123-45-6789');
  iu.run('alice', 'password123', 'alice@email.com', 'user', '4111-XXXX-XXXX-1111', '987-65-4321');
  iu.run('bob', 'letmein', 'bob@email.com', 'user', '5500-XXXX-XXXX-2222', '456-78-9123');
  iu.run(
    'charlie',
    'qwerty',
    'charlie@email.com',
    'user',
    '3400-XXXX-XXXX-3333',
    'FLAG{api_bola_api1_8c2d4}'
  );

  db.prepare('INSERT INTO api_keys (user_id, api_key, access_level) VALUES (?,?,?)').run(
    1,
    'sk-admin-key-xxxx',
    'admin'
  );
  db.prepare('INSERT INTO posts (user_id, title, content) VALUES (?,?,?)').run(
    1,
    'Welcome to VulnLab',
    'This is a vulnerable lab.'
  );
  db.prepare('INSERT INTO posts (user_id, title, content) VALUES (?,?,?)').run(
    2,
    'My first hack',
    'SQL injection is fun <script>alert(1)</script>'
  );
  db.prepare('INSERT INTO products (name, price, description) VALUES (?,?,?)').run(
    'Premium Account',
    49.99,
    'Full access'
  );
  db.prepare('INSERT INTO products (name, price, description) VALUES (?,?,?)').run(
    'Basic Account',
    9.99,
    'Limited access'
  );
  db.prepare(
    'INSERT INTO credit_cards (user_id, card_number, cvv, exp_date, cardholder_name) VALUES (?,?,?,?,?)'
  ).run(1, '4532-1122-3344-5566', '123', '12/27', 'Admin User');
}

module.exports = db;
