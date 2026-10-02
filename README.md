# 🛡️ TrustShield — Fake News & Phishing Message Detector

A lightweight, browser-based tool that analyzes text for signs of phishing attacks and misinformation using a multi-signal heuristic engine.

---

## 📁 Project Structure

```
fake-news-detector/
├── index.html          # Main application UI
├── css/
│   └── style.css       # Dark-theme responsive stylesheet
├── js/
│   ├── detector.js     # Core detection engine
│   └── app.js          # UI controller
└── README.md
```

---

## 🚀 Getting Started

Just open `index.html` in any modern browser — no build tools, no dependencies, no server required.

```bash
# Or serve locally with any static server, e.g.:
npx serve fake-news-detector
```

---

## 🔍 Detection Capabilities

### 🎣 Phishing Detection
| Signal | Description |
|--------|-------------|
| **Keyword Matching** | 50+ known phishing phrases (account suspended, verify now, etc.) |
| **URL Analysis** | IP-based URLs, shorteners, lookalike typo-squatting domains |
| **Urgency Language** | "Within 24 hours", "act now", "final notice", etc. |
| **Personal Info Requests** | Password, SSN, credit card, bank account prompts |
| **Style Signals** | Excessive CAPS, multiple exclamation marks |

### 📰 Fake News Detection
| Signal | Description |
|--------|-------------|
| **Misinformation Keywords** | "What they don't want you to know", "mainstream media won't tell you", etc. |
| **Conspiracy Framing** | Deep state, new world order, 5G, vaccine microchips, etc. |
| **Sensational Language** | Shocking, explosive, jaw-dropping, bombshell, etc. |
| **Emotional Manipulation** | "Share before deleted", "tell everyone", "pass it on" |
| **Vague Conspiracy Pronouns** | Excessive use of "they/them" without attribution |
| **Unreliable Sources** | Matches against known fake news domain patterns |

---

## 📊 Scoring System

| Score Range | Confidence | Meaning |
|-------------|-----------|---------|
| 0 – 9       | NONE      | No significant threats detected |
| 10 – 34     | LOW       | Minor suspicious signals |
| 35 – 69     | MEDIUM    | Likely phishing or misinformation |
| 70 – 100    | HIGH      | Strong indicators — treat as threat |

---

## 💡 Features

- ✅ **Zero dependencies** — pure HTML, CSS, JavaScript
- ✅ **Dark UI** — easy on the eyes with a professional design
- ✅ **Dual scoring** — separate phishing and fake news scores
- ✅ **Signal breakdown** — every detected flag is listed with an explanation
- ✅ **Example messages** — one-click load of phishing, fake news, and safe examples
- ✅ **Animated score bars** — visual representation of risk levels
- ✅ **Fully responsive** — works on desktop and mobile

---

## ⚠️ Disclaimer

This tool is for **educational and demonstration purposes only**. It uses static heuristic rules and is not a substitute for:
- Professional email security gateways
- AI/ML-based phishing classifiers
- Verified fact-checking platforms (Snopes, FactCheck.org, etc.)

Always cross-reference suspicious content with authoritative sources.

---

## 🔮 Possible Enhancements

- [ ] Integrate with Google Safe Browsing API for real-time URL checks
- [ ] Add VirusTotal API for domain reputation lookups
- [ ] Connect to a fact-checking API (e.g., ClaimBuster)
- [ ] Train a lightweight ML model on labeled datasets
- [ ] Add browser extension packaging (Manifest V3)
- [ ] Export analysis report as PDF

---

*Built with vanilla JavaScript — no frameworks, no tracking, no external requests.*
