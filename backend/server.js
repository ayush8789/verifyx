// backend/server.js
// VerifyX backend - Express server
// Endpoints:
//  POST /api/verify      - analyze { type, value } JSON body
//  GET  /api/verify?value=... - convenience browser endpoint
//  POST /api/report      - save a report to SQLite
//  GET  /api/reports     - list recent reports
//  GET  /                 - simple health/welcome

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');            // sqlite helper (creates DB)
const { analyze } = require('./lib/checker'); // upgraded analyzer

const app = express();

// Middlewares
app.use(cors()); // in production you can restrict origin: app.use(cors({ origin: 'https://your-frontend.vercel.app' }))
app.use(bodyParser.json({ limit: '200kb' }));

// POST /api/verify - primary endpoint used by frontend
app.post('/api/verify', (req, res) => {
  const { type = 'text', value } = req.body || {};
  if (!value) return res.status(400).json({ error: 'missing value' });

  try {
    const result = analyze(type, value);
    return res.json(result);
  } catch (err) {
    console.error('Error in /api/verify POST:', err);
    return res.status(500).json({ error: err.message });
  }
});

// Convenience: GET /api/verify?value=... for quick browser testing
app.get('/api/verify', (req, res) => {
  const value = req.query.value;
  if (!value) return res.status(400).json({ error: 'missing value (use ?value=...)' });

  try {
    const result = analyze('text', value);
    return res.json(result);
  } catch (err) {
    console.error('Error in /api/verify GET:', err);
    return res.status(500).json({ error: err.message });
  }
});

// Simple root for health-checks
app.get('/', (req, res) => {
  res.send('VerifyX backend is running. Use POST /api/verify or GET /api/verify?value=...');
});

// POST /api/report - store a reported suspicious example
app.post('/api/report', (req, res) => {
  const { type = 'text', value, reasons = [], score = 0 } = req.body || {};
  if (!value) return res.status(400).json({ error: 'missing value' });

  const stmt = db.prepare("INSERT INTO reports (type, value, reasons, score) VALUES (?, ?, ?, ?)");
  stmt.run(type, value, JSON.stringify(reasons), score, function (err) {
    if (err) {
      console.error('DB insert error:', err);
      return res.status(500).json({ error: err.message });
    }
    return res.json({ ok: true, id: this.lastID });
  });
  stmt.finalize();
});

// GET /api/reports - list latest reports
app.get('/api/reports', (req, res) => {
  db.all('SELECT id, type, value, reasons, score, created_at FROM reports ORDER BY created_at DESC LIMIT 100', (err, rows) => {
    if (err) {
      console.error('DB select error:', err);
      return res.status(500).json({ error: err.message });
    }
    // parse reasons back to arrays
    rows = rows.map(r => ({ ...r, reasons: (function(){ try { return JSON.parse(r.reasons); } catch(e){ return []; } })() }));
    return res.json(rows);
  });
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`VerifyX backend listening on port ${PORT}`);
});
