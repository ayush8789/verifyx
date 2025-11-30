// backend/server.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { analyze } = require('./lib/checker');
const db = require('./db');

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '200kb' }));

app.post('/api/verify', (req, res) => {
  const { type = 'text', value } = req.body;
  if(!value) return res.status(400).json({ error: 'missing value' });
  try {
    const result = analyze(type, value);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/report', (req, res) => {
  const { type='text', value, reasons, score } = req.body;
  const stmt = db.prepare("INSERT INTO reports (type, value, reasons, score) VALUES (?, ?, ?, ?)");
  stmt.run(type, value, JSON.stringify(reasons || []), score || 0, function(err){
    if(err) return res.status(500).json({error: err.message});
    res.json({ ok: true, id: this.lastID });
  });
  stmt.finalize();
});

app.get('/api/reports', (req, res) => {
  db.all('SELECT id, type, value, reasons, score, created_at FROM reports ORDER BY created_at DESC LIMIT 50', (err, rows) => {
    if(err) return res.status(500).json({ error: err.message });
    rows = rows.map(r => ({ ...r, reasons: (() => { try { return JSON.parse(r.reasons); } catch(e){ return []; } })() }));
    res.json(rows);
  });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('Backend running on port', PORT));
