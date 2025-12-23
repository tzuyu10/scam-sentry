import { useState } from 'react';
import { scanMessage } from './utils/utils';
import './App.css';

function App() {
  const [input, setInput] = useState('');
  const [res, setRes] = useState<{ score: number; matches: any[] } | null>(null);

  const handle = () => setRes(scanMessage(input));

  return (
    <div className="container">
      <h1>ScamSentry – FFA Demo</h1>
      <textarea
        rows={6}
        cols={70}
        value={input}
        onChange={e => setInput(e.target.value)}
        placeholder="Paste SMS / chat message here…"
      />
      <br />
      <button onClick={handle}>Analyse</button>

      {res && (
        <div className="result">
          <h2>Risk Score: {res.score}/100</h2>
          <ul>
            {res.matches.map((m, i) => (
              <li key={i}>
                <strong>{m.category}</strong> – {m.pattern} (w={m.weight})
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;