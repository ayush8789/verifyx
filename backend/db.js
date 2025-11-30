// backend/db.js
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'verifyx.db');

const db = new sqlite3.Database(DB_PATH);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,
    value TEXT,
    reasons TEXT,
    score INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  console.log('DB ready at', DB_PATH);
});

if (require.main === module) {
  db.close();
}

module.exports = db;
