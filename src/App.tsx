import { useState } from 'react';
import { scanMessage } from './utils/utils';
import { hybridAnalyze } from './utils/hybridScorer';
import type { ScanResult } from './types/types';
import './App.css';

function App() {
  const [input, setInput] = useState('');
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [hybrid, setHybrid] = useState<any>(null);

  const handleAnalyze = () => {
    if (!input.trim()) return;

    const scanResult = scanMessage(input);
    const hybridResult = hybridAnalyze(scanResult, input);

    setScan(scanResult);
    setHybrid(hybridResult);
  };

  const clear = () => {
    setInput('');
    setScan(null);
    setHybrid(null);
  };

  return (
    <div className="container">
      <h1>🛡 ScamSentry</h1>

      <textarea
        rows={6}
        cols={70}
        value={input}
        onChange={e => setInput(e.target.value)}
        placeholder="Paste SMS / chat message here…"
      />

      <div className="button-group">
        <button onClick={handleAnalyze}>Analyze</button>
        <button className="clear-button" onClick={clear}>Clear</button>
      </div>

      {scan && hybrid && (
        <div className="result">
          <h2>Results</h2>

          <p><strong>DFA Score:</strong> {hybrid.dfaScore}/100</p>
          <p>
            <strong>Hybrid Score:</strong>{' '}
            <span className={`risk-${hybrid.riskLevel.toLowerCase()}`}>
              {hybrid.hybridScore}/100 ({hybrid.riskLevel})
            </span>
          </p>

          <h3>Detected Patterns</h3>
          <ul>
            {scan.matches.map((m, i) => (
              <li key={i}>
                <strong>{m.category}</strong> – {m.pattern} (w={m.weight})
              </li>
            ))}
          </ul>

          <h3>Extracted Features (ML)</h3>
          <pre>
            {JSON.stringify(hybrid.features, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export default App;
