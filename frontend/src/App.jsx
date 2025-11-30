import React, {useState} from 'react';

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
        body: JSON.stringify({ type:'text', value, reasons: res.reasons, score: res.score })
      });
      alert('Reported — thank you!');
    } catch (e) {
      alert('Report failed: ' + e.message);
    }
  };

  return (
    <div className="container">
      <h1>VerifyX — Job/Internship Verifier</h1>
      <p>Paste job post text, URL, or offer email here and click <b>Verify</b>.</p>
      <textarea className="input" value={value} onChange={e=>setValue(e.target.value)} rows={8} placeholder="Paste job text / URL / email..." />
      <div style={{marginTop:12}}>
        <button onClick={verify} disabled={loading} className="btn">{loading ? 'Checking…' : 'Verify'}</button>
      </div>

      {res && (
        <div className="result">
          {res.error ? (
            <div className="error">Error: {res.error}</div>
          ) : (
            <>
              <div className="scoreRow">
                <div className={'badge ' + res.level}>{res.level.toUpperCase()}</div>
                <div style={{marginLeft:12}}><strong>Score:</strong> {res.score}</div>
              </div>
              <ul className="reasons">
                {res.reasons.map((r,i)=>(<li key={i}>{r}</li>))}
              </ul>
              <div style={{marginTop:8}}>
                <button onClick={report} className="btn small">Report</button>
              </div>
            </>
          )}
        </div>
      )}
      <footer style={{marginTop:24, color:'#666'}}>Tip: Try pasting "processing fee" text to see detection.</footer>
    </div>
  );
}
