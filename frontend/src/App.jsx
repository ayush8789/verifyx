import React, { useState } from 'react';

const API = process.env.REACT_APP_API_URL || 'http://localhost:4000';

export default function App(){
  const [value, setValue] = useState('');
  const [res, setRes] = useState(null);
  const [loading, setLoading] = useState(false);

  const verify = async () => {
    if(!value.trim()){
      alert('Paste job text, URL, or email.');
      return;
    }
    setLoading(true); setRes(null);
    try {
      const r = await fetch(API + '/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'text', value })
      });
      const j = await r.json();
      setRes(j);
    } catch (e) {
      setRes({ error: e.message });
    } finally {
      setLoading(false);
    }
  };

  const report = async () => {
    if(!res) return;
    try {
      await fetch(API + '/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type:'text', value, reasons: res.reasons || [], score: res.score || 0 })
      });
      alert('Reported — thank you!');
    } catch (e) {
      alert('Report failed: ' + e.message);
    }
  };

  return (
    <div className="container" style={{ maxWidth: 780, margin: '36px auto', padding: 20, background: '#fff', borderRadius: 8, boxShadow: '0 6px 20px rgba(0,0,0,0.04)' }}>
      <h1 style={{ margin: 0, fontSize: 22 }}>VerifyX — Job/Internship Verifier</h1>
      <p style={{ marginTop: 8 }}>Paste job post text, URL, or offer email here and click <b>Verify</b>.</p>

      <textarea
        className="input"
        value={value}
        onChange={e=>setValue(e.target.value)}
        rows={8}
        placeholder="Paste job text / URL / email..."
        style={{ width: '100%', padding: 12, borderRadius: 6, border: '1px solid #ddd', fontSize: 14, boxSizing: 'border-box' }}
      />

      <div style={{ marginTop: 12 }}>
        <button onClick={verify} disabled={loading} className="btn" style={{ background: '#0b5ed7', color: '#fff', border: 'none', padding: '8px 14px', borderRadius: 6, cursor: loading ? 'default' : 'pointer' }}>
          {loading ? 'Checking…' : 'Verify'}
        </button>
      </div>

      {res && (
        <div className="result" style={{ marginTop: 16, border: '1px solid #eee', padding: 12, borderRadius: 6, background: '#fafafa' }}>
          {res.error ? (
            <div className="error" style={{ color: '#c00' }}>Error: {res.error}</div>
          ) : (
            <>
              <div className="scoreRow" style={{ display: 'flex', alignItems: 'center' }}>
                <div className={'badge ' + (res.level || '').toLowerCase()} style={{
                  display: 'inline-block',
                  padding: '6px 10px',
                  borderRadius: 6,
                  color: '#fff',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  background: res.level === 'red' ? '#dc3545' : res.level === 'yellow' ? '#ffc107' : '#28a745'
                }}>
                  {(res.level || '').toUpperCase() || 'UNKNOWN'}
                </div>
                <div style={{ marginLeft: 12 }}><strong>Score:</strong> {typeof res.score === 'number' ? res.score : '—'}</div>
              </div>

              <ul className="reasons" style={{ marginTop: 8 }}>
                {(res.reasons && res.reasons.length > 0) ? (
                  res.reasons.map((r,i)=>(<li key={i}>{r}</li>))
                ) : (
                  <li>No detailed reasons provided.</li>
                )}
              </ul>

              <div style={{ marginTop: 8 }}>
                <button onClick={report} className="btn small" style={{ background: '#0b5ed7', color: '#fff', border: 'none', padding: '6px 10px', borderRadius: 6 }}>
                  Report
                </button>
              </div>
            </>
          )}
        </div>
      )}

      <footer style={{ marginTop: 24, color: '#666' }}>Tip: Try pasting "processing fee" text to see detection.</footer>

      {/* FOOTER CREDIT */}
      <footer style={{ marginTop: 28, textAlign: 'center', fontSize: 14, color: '#555', paddingBottom: 20 }}>
        Built by Ayush Singh © 2025
      </footer>
    </div>
  );
}
