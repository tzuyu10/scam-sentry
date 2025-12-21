# ScamSentry

A real-time scam detection system using Deterministic Finite Automata (DFA) and the Aho-Corasick algorithm to identify suspicious patterns in text messages.

---

## Description

ScamSentry detects scam messages by analyzing text for suspicious patterns across 5 categories:

- **Urgency** - Time pressure phrases ("urgent", "act now", "expires")
- **Financial** - Money-related terms ("loan", "prize", "instant pera")
- **Phishing** - Account verification requests ("verify account", "enter OTP")
- **Impersonation** - Fake authority claims ("BPI", "GCash", "BIR")
- **URL** - Suspicious links ("bit.ly", ".tk domains")

The system processes 60+ patterns simultaneously and generates a risk score (0-100) with color-coded alerts.

---

## How the DFA Works

### 1. **Pattern Storage (Trie Structure)**
All patterns are stored in a tree structure where each character is a node:

```
Example for "urgent" and "url":
       root (q0)
       /    \
      u      (other chars)
     /
    r
   /
  g
 /
e
/
n
/
t  ← accepting state (outputs "urgent", weight: 0.90)
```

### 2. **State Transitions (δ: Q × Σ → Q)**
The DFA reads text character by character and transitions between states:

```
Input: "URGENT loan"
       
Step 1: Read 'U' → transition to state q_u
Step 2: Read 'R' → transition to state q_ur  
Step 3: Read 'G' → transition to state q_urg
Step 4: Read 'E' → transition to state q_urge
Step 5: Read 'N' → transition to state q_urgen
Step 6: Read 'T' → transition to accepting state
        ✓ MATCH FOUND: "urgent" (weight: 0.90)
```

### 3. **Failure Links (Aho-Corasick Optimization)**
When no direct transition exists, failure links avoid reprocessing:

```
Current state: q_act (matched "ac")
Next char: 'x' (no transition for 'x')
Action: Follow failure link back to root
Result: Continue from root without rescanning
```

### 4. **Multi-Pattern Matching**
All 5 DFA modules run in parallel, processing the entire text in one pass:

```
Input: "URGENT! Your GCash account suspended. Verify now!"

Urgency DFA:    ✓ "urgent" (0.90), "suspended" (0.95)
Financial DFA:  (no matches)
Phishing DFA:   ✓ "verify" (0.85)
Impersonation:  ✓ "gcash" (0.85)
URL DFA:        (no matches)

Total: 4 patterns detected across 3 categories
```

### 5. **Risk Score Calculation**
```
For each category:
  categoryScore = (maxWeight × 0.7 + avgWeight × 0.3) × (1 + log₁₀(matches))

Example:
  Urgency: (0.95 × 0.7 + 0.925 × 0.3) × 1.30 = 1.23
  Phishing: (0.85 × 0.7 + 0.85 × 0.3) × 1.00 = 0.85
  Impersonation: (0.85 × 0.7 + 0.85 × 0.3) × 1.00 = 0.85

Total Score: (1.23 + 0.85 + 0.85) × 100 = 293 → capped at 100
Risk Level: CRITICAL 
```

---

## How to Run

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/scamsentry.git
cd scamsentry

# Install dependencies
npm install

# Start development server
npm run dev
```

Open browser to `http://localhost:5173`

### Build for Production

```bash
npm run build
npm run preview
```

---

## Project Structure

```
scamsentry/
├── src/
│   ├── classes/
│   │   ├── DFANode.ts           # DFA state implementation
│   │   └── AhoCorasickDFA.ts    # Pattern matching algorithm
│   ├── data/
│   │   └── patterns.ts          # 60 scam patterns
│   ├── utils/
│   │   └── utils.ts             # Scoring functions
│   ├── constants/
│   │   └── constants.ts         # App constants
│   ├── types.ts                 # TypeScript types
│   └── App.tsx                  # Main component
└── package.json
```

---

## Usage Example

```typescript
// Example scam message
"URGENT! Your GCash account has been suspended. 
Verify account now by clicking: bit.ly/verify123"

// Detection results:
Risk Score: 100.00
Risk Level: CRITICAL
Patterns Found:
  - "urgent" (Urgency, weight: 0.90)
  - "gcash" (Impersonation, weight: 0.85)
  - "suspended" (Urgency, weight: 0.95)
  - "verify account" (Phishing, weight: 0.95)
  - "bit.ly" (URL, weight: 0.90)
```

---

## Academic Context

**Project for**: COSC 302: Automata and Language Theory  
**Group**: Group 6, BSCS 3-5  

### Team Members
- Cansino, Florence Lee F.
- Faeldonia, Elias Von Isaac R.
- Lucero, Ken Audie S.
- Magtanong, Gabriel Andre E.

---

## References

- Sisto, R. (2020). FSA-based Packet Filters
- Krishnan, A. V. (2020). Finite Automata for Fake Profile Identification
- Kalpen, A. K., et al. (2025). Sequence Recognition using Finite Automata

---
