import { useState } from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle, XCircle, Trash2 } from 'lucide-react';
import { scanMessage } from './utils/utils';
import { hybridAnalyze } from './utils/hybridScorer';
import type { ScanResult } from './types/types';
import ScamSentryLogo from './assets/ScamSentryLogoDark.svg';
import ScamSentryLogo1 from './assets/ScamSentryLogo.svg';
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

  const getRiskColor = (level: string) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL': return 'text-red-600';
      case 'HIGH': return 'text-orange-600';
      case 'MEDIUM': return 'text-yellow-600';
      case 'LOW': return 'text-green-600';
      default: return 'text-gray-600';
    }
  };

  const getRiskIcon = (level: string) => {
    switch (level?.toUpperCase()) {

      case 'CRITICAL': return <ShieldAlert className="w-6 h-6" />;
      case 'HIGH': return <XCircle className="w-6 h-6" />;
      case 'MEDIUM': return <AlertTriangle className="w-6 h-6" />;
      case 'LOW': return <CheckCircle className="w-6 h-6" />;
      default: return null;
    }
  };

  return (
    <div className="app-container">
      <div className="content-wrapper">
        <div className="main-content">
          {/* Header */}
          <div className="header">
            <div className="header-title">
              <img src={ScamSentryLogo} alt="ScamSentry Logo"/>
              <h1>ScamSentry</h1>
            </div>
            <p className="header-subtitle">Scam Text Message Analyzation System</p>
          </div>

          {/* Input Section */}
          <div className="input-section">
            <label className="input-label">Message to Analyze</label>
            <textarea
              rows={6}
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder="Paste any suspicious SMS, or chat message here for analysis... up to 1000 characters."
              className="message-input"
            />

            <div className="button-group">
              <button
                onClick={handleAnalyze}
                disabled={!input.trim()}
                className="analyze-button"
              >
                Analyze Message
              </button>
              <button onClick={clear} className="clear-button">
                <Trash2 className="w-4 h-4" />
                Clear
              </button>
            </div>
          </div>

          {/* Results Section */}
          {scan && hybrid && (
            <div className="results-container">
              {/* Risk Summary Banner */}
              <div className={`risk-banner risk-${hybrid.riskLevel.toLowerCase()}`}>
                <div className="risk-banner-content">
                  <div className="risk-info">
                    <div className={getRiskColor(hybrid.riskLevel)}>
                      {getRiskIcon(hybrid.riskLevel)}
                    </div>
                    <div>
                      <h2 className="risk-title">{hybrid.riskLevel} Risk Detected</h2>
                      <p className="risk-description">
                        {hybrid.riskLevel === 'CRITICAL' && 'This message is extremely likely to be a scam. Immediate caution is advised.'}
                        {hybrid.riskLevel === 'HIGH' && 'This message shows strong signs of a scam. Do not respond or click any links.'}
                        {hybrid.riskLevel === 'MEDIUM' && 'This message contains suspicious elements. Verify sender authenticity before responding.'}
                        {hybrid.riskLevel === 'LOW' && 'This message appears relatively safe, but always stay vigilant.'}
                      </p>
                    </div>
                  </div>
                  <div className="risk-score">
                    <div className="score-number">{hybrid.hybridScore}</div>
                    <div className="score-label">Risk Score</div>
                  </div>
                </div>
              </div>

              {/* Detailed Scores */}
              <div className="scores-grid">
                <div className="score-card">
                  <div className="score-card-label">Pattern Score</div>
                  <div className="score-card-value">
                    <span className="score-value">{hybrid.dfaScore}</span>
                    <span className="score-max">/ 100</span>
                  </div>
                  <div className="progress-bar">
                    <div 
                      className="progress-fill progress-blue"
                      style={{ width: `${hybrid.dfaScore}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Detected Patterns */}
              <div className="section">
                <h3 className="section-title">Detected Scam Patterns</h3>
                {scan.matches.length > 0 ? (
                  <div className="patterns-list">
                    {scan.matches.map((m: any, i: number) => (
                      <div key={i} className="pattern-item">
                        <div className="pattern-icon">
                          <AlertTriangle className="w-5 h-5" />
                        </div>
                        <div className="pattern-details">
                          <div className="pattern-category">{m.category}</div>
                          <div className="pattern-text">"{m.pattern}"</div>
                          <div className="pattern-weight">Weight: {m.weight.toFixed(2)}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="no-patterns">No suspicious patterns detected</p>
                )}
              </div>

              {/* Extracted Features */}
              <div className="section">
                <h3 className="section-title">Extracted Features</h3>
                <div className="features-grid">
                  {Object.entries(hybrid.features).map(([key, value]: [string, any]) => (
                    <div key={key} className="feature-item">
                      <div className="feature-label">{key}</div>
                      <div className="feature-value">{String(value)}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Footer */}
      <footer className="footer">
        <div className="footer-content">
          <div className="footer-section">
            <div className="footer-brand">
              <img src={ScamSentryLogo1} alt="ScamSentry Logo White"/>
              <span>ScamSentry</span>
            </div>
            <p className="footer-text">Protecting users from digital scam messages</p>
          </div>
          <div className="footer-section">
            <h4 className="footer-heading">About</h4>
            <p className="footer-text">ScamSentry uses DFA pattern and Aho Corasick Algorithm recognition to identify potential scams in messages.</p>
          </div>
          <div className="footer-section">
            <h4 className="footer-heading">Disclaimer</h4>
            <p className="footer-text">This tool provides analysis for educational purposes. Created by Group 6 of BSCS 3-5 students. Always verify suspicious messages independently. </p>
          </div>
        </div>
        <div className="footer-bottom">
          <p>&copy; 2026 ScamSentry. CANSINO | FAELDONIA | LUCERO | MAGTANONG.</p>
        </div>
      </footer>
    </div>
  );
}

export default App;