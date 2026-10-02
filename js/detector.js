/**
 * TrustShield — Fake News & Phishing Message Detector
 * Detection Engine v2.0 — Extended heuristic + keyword-based analysis
 */

// ─── Phishing Signals ────────────────────────────────────────────────────────

const PHISHING_KEYWORDS = [
  // Account & identity
  "verify your account", "confirm your identity", "validate your information",
  "update your payment", "update your billing", "update your details",
  "your account has been suspended", "your account will be closed",
  "your account has been locked", "account termination notice",
  "unusual activity detected", "suspicious login detected",
  "unauthorized access", "unauthorized login", "security alert",
  "login attempt", "failed login",
  // Credential harvesting
  "enter your password", "provide your credentials", "submit your details",
  "re-enter your details", "confirm your email", "verify your email",
  "reset your password", "update your password",
  // Financial
  "bank details", "bank account number", "credit card number", "wire transfer",
  "unclaimed funds", "release of funds", "transfer of funds",
  // Gift card / crypto scams
  "bitcoin payment", "gift card", "itunes card", "google play card",
  "steam wallet", "amazon gift card", "purchase gift cards",
  // Prizes / lottery
  "you have won", "you've been selected", "congratulations you've been selected",
  "claim your prize", "claim your reward", "free gift", "you are a winner",
  "lottery winner", "lucky winner",
  // Inheritance / Nigerian advance fee
  "nigerian prince", "inheritance fund", "next of kin", "foreign fund",
  "transfer of inheritance",
  // Generic social engineering
  "dear customer", "dear user", "dear account holder", "dear valued member",
  "dear client", "to the owner of this email",
  // Brand impersonation
  "your paypal", "your amazon account", "your netflix account",
  "your apple id", "your google account", "your microsoft account",
  "your bank account", "your chase account", "your wells fargo",
  // Action prompts
  "click here immediately", "click the link below", "follow this link",
  "verify now", "confirm now", "act now", "limited time offer",
  "urgent action required", "immediate action required",
  // Tech support scams
  "your computer has been hacked", "your device is infected",
  "call our toll-free number", "microsoft support",
  "your warranty has expired", "virus detected on your computer",
];

const PHISHING_URL_PATTERNS = [
  /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,            // IP address URLs
  /bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|short\.io|rebrand\.ly|cutt\.ly/i, // URL shorteners
  /paypa1|paypai|arnazon|g00gle|micros0ft|appie|netfl1x|faceb00k|tw1tter/i, // Lookalike
  /\.tk$|\.ml$|\.ga$|\.cf$|\.gq$|\.xyz$|\.top$|\.click$|\.link$/i, // Suspicious TLDs
  /login[-.]|[-.]login|secure[-.]|[-.]secure|verify[-.]|[-.]verify/i,
  /account[-.]update|update[-.]account|confirm[-.]email|signin[-.]|[-.]signin/i,
  /[a-z0-9]{20,}\.(com|net|org)/i,                               // Long random domains
  /https?:\/\/[^/]+\.[^/]+\/[a-z0-9]{8,}$/i,                    // Random path tokens
];

const URGENCY_PHRASES = [
  "immediately", "right now", "within 24 hours", "within 48 hours",
  "within the next hour", "respond within", "expires in",
  "do not ignore", "failure to respond", "your account will be terminated",
  "respond asap", "time sensitive", "time-sensitive", "expires today",
  "last chance", "act fast", "hurry", "don't delay", "before it's too late",
  "final notice", "last warning", "last reminder", "this is your final",
  "you must respond", "reply immediately", "contact us immediately",
  "do not delete this", "do not discard",
];

const PERSONAL_INFO_PATTERNS = [
  { pattern: /password|passwd|passphrase/i,           label: "password" },
  { pattern: /credit.?card|card.?number|cvv|cvc/i,    label: "credit card" },
  { pattern: /social.?security|ssn/i,                 label: "Social Security Number" },
  { pattern: /date.?of.?birth|\bdob\b/i,              label: "date of birth" },
  { pattern: /bank.?account|routing.?number/i,        label: "bank account" },
  { pattern: /\bpin\b.{0,10}number|atm.{0,5}pin/i,   label: "PIN number" },
  { pattern: /driver.{0,5}licen[cs]e/i,               label: "driver's license" },
  { pattern: /passport.{0,10}number/i,                label: "passport number" },
  { pattern: /mother.{0,10}maiden/i,                  label: "mother's maiden name" },
];

// Sender/header spoofing cues (in email body text)
const SPOOFING_CUES = [
  "noreply@", "no-reply@", "donotreply@",
  "support@paypa", "support@amazon-", "security@apple-",
  "admin@microsoft-", "help@netflix-",
  "from: paypal", "from: amazon", "from: apple",
];

// ─── Fake News Signals ───────────────────────────────────────────────────────

const FAKE_NEWS_KEYWORDS = [
  // Media distrust
  "mainstream media won't tell you", "what they don't want you to know",
  "they're hiding this", "media blackout", "censored by mainstream media",
  "the truth mainstream media", "msm won't report",
  // Medical misinformation
  "secret cure", "miracle cure", "doctors hate", "doctors won't tell you",
  "your doctor is hiding", "100% proven", "guaranteed results",
  "big pharma doesn't want you to know", "natural cure they suppressed",
  "fda doesn't want you", "banned by doctors",
  // Deletion / censorship urgency
  "share before deleted", "share before they take it down",
  "censored by", "banned video", "banned by youtube",
  "they will remove this", "before it's removed",
  "watch before censored", "deleted by facebook",
  // Conspiracy theories
  "wake up sheeple", "deep state", "new world order", "illuminati",
  "bill gates microchip", "5g causes", "vaccine contains",
  "chemtrails", "flat earth", "lizard people", "crisis actors",
  "false flag", "hoax exposed", "fake pandemic", "plandemic",
  "government is hiding", "cover up", "conspiracy revealed",
  "they planned this", "it's all planned",
  // Pseudo-science
  "suppressed technology", "free energy suppressed", "nikola tesla secret",
  "cure for cancer they're hiding", "ancient remedy",
  // Emotional / viral manipulation
  "breaking exclusive", "shocking truth", "you won't believe",
  "share this now before it's removed", "forward to everyone",
  "this video will shock you", "the truth about",
  "if you believe in freedom share this",
  "pass this on to everyone you know",
  "every patriot should see this",
  "they don't want this to go viral",
];

const SENSATIONAL_WORDS = [
  "shocking", "explosive", "bombshell", "mind-blowing", "unbelievable",
  "incredible", "stunning", "outrageous", "jaw-dropping", "terrifying",
  "horrifying", "devastating", "game-changer", "earth-shattering",
  "revolutionary", "miracle", "secret", "exposed", "leaked",
  "banned", "suppressed", "exclusive", "breaking", "urgent",
  "alert", "warning", "must read", "must watch", "must share",
];

const CLICKBAIT_PATTERNS = [
  /\d+\s+(reasons|things|ways|facts|secrets|tricks)\s+(you|that|why|to)/i,
  /what happened next will (shock|amaze|surprise) you/i,
  /you won'?t believe (what|how|who|why)/i,
  /this (one|simple) (trick|secret|hack)/i,
  /doctors (hate|don'?t want you to know)/i,
  /\[MUST (READ|WATCH|SEE)\]/i,
];

const UNRELIABLE_SOURCE_PATTERNS = [
  /worldnewsdailyreport/i, /empirenews/i, /huzlers/i, /nationalreport/i,
  /theonion/i, /clickhole/i, /realnewsrightnow/i, /topekacapitaljournal/i,
  /newsbiscuit/i, /thespoof/i, /abcnews\.com\.co/i, /cbsnews\.com\.co/i,
  /conservativedailypost/i, /beforeitsnews/i, /yournewswire/i,
  /infowars/i, /naturalnews/i, /activistpost/i,
];

// ─── Readability & Grammar Analysis ─────────────────────────────────────────

function analyzeReadability(text) {
  const sentences = text.match(/[^.!?]+[.!?]+/g) || [text];
  const words = text.trim().split(/\s+/);
  const syllables = words.reduce((sum, w) => sum + countSyllables(w), 0);

  const avgWordsPerSentence = words.length / Math.max(sentences.length, 1);
  const avgSyllablesPerWord = syllables / Math.max(words.length, 1);

  // Flesch-Kincaid Grade Level
  const fkGrade = 0.39 * avgWordsPerSentence + 11.8 * avgSyllablesPerWord - 15.59;

  // Flesch Reading Ease (higher = easier)
  const readingEase = 206.835 - 1.015 * avgWordsPerSentence - 84.6 * avgSyllablesPerWord;

  return {
    sentenceCount: sentences.length,
    avgWordsPerSentence: Math.round(avgWordsPerSentence * 10) / 10,
    fkGrade: Math.round(Math.max(0, fkGrade) * 10) / 10,
    readingEase: Math.round(Math.min(100, Math.max(0, readingEase)) * 10) / 10,
    readingLevel: getReadingLevel(readingEase),
  };
}

function countSyllables(word) {
  word = word.toLowerCase().replace(/[^a-z]/g, "");
  if (word.length <= 3) return 1;
  word = word.replace(/(?:[^laeiouy]es|ed|[^laeiouy]e)$/, "");
  word = word.replace(/^y/, "");
  const m = word.match(/[aeiouy]{1,2}/g);
  return m ? m.length : 1;
}

function getReadingLevel(ease) {
  if (ease >= 90) return "Very Easy";
  if (ease >= 80) return "Easy";
  if (ease >= 70) return "Fairly Easy";
  if (ease >= 60) return "Standard";
  if (ease >= 50) return "Fairly Difficult";
  if (ease >= 30) return "Difficult";
  return "Very Confusing";
}

// ─── URL Extractor ────────────────────────────────────────────────────────────

function extractURLs(text) {
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
  return text.match(urlRegex) || [];
}

function classifyURL(url) {
  const issues = [];
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) issues.push("IP address (no domain)");
  if (/bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|short\.io|rebrand\.ly|cutt\.ly/.test(url)) issues.push("URL shortener");
  if (/paypa1|paypai|arnazon|g00gle|micros0ft|appie|netfl1x|faceb00k/.test(url)) issues.push("Lookalike/typosquat domain");
  if (/\.tk$|\.ml$|\.ga$|\.cf$|\.gq$|\.xyz$|\.top$|\.click$|\.link$/.test(url)) issues.push("Suspicious free TLD");
  if (/login[-.]|[-.]login|secure[-.]|verify[-.]/.test(url)) issues.push("Deceptive subdomain");
  if (url.length > 100) issues.push("Unusually long URL");
  return issues;
}

// ─── Scoring Engine ──────────────────────────────────────────────────────────

/**
 * @param {string} text
 * @returns {AnalysisResult}
 */
function analyzeText(text) {
  if (!text || text.trim().length < 10) return null;

  const lower = text.toLowerCase();
  const words = text.trim().split(/\s+/);

  // Categorized flags: { severity: 'high'|'medium'|'low', category: string, message: string }
  const flagObjects = [];
  let phishingScore = 0;
  let fakeNewsScore = 0;

  const addFlag = (severity, category, message) => {
    flagObjects.push({ severity, category, message });
  };

  // ── Phishing checks ──────────────────────────────────────────────────────

  // Keyword matches
  PHISHING_KEYWORDS.forEach((kw) => {
    if (lower.includes(kw)) {
      phishingScore += 12;
      addFlag("high", "phishing", `🎣 Phishing keyword: "${kw}"`);
    }
  });

  // URL analysis
  const urls = extractURLs(text);
  urls.forEach((url) => {
    const issues = classifyURL(url);
    if (issues.length > 0) {
      phishingScore += 18 * issues.length;
      issues.forEach((issue) => {
        addFlag("high", "url", `🔗 Suspicious URL [${issue}]: ${url.substring(0, 55)}${url.length > 55 ? "…" : ""}`);
      });
    }
  });

  // URL-to-text ratio (phishing emails often have many links relative to text)
  const urlToWordRatio = urls.length / Math.max(words.length, 1);
  if (urls.length >= 2 && urlToWordRatio > 0.05) {
    phishingScore += 10;
    addFlag("medium", "url", `🔗 High link density: ${urls.length} URL(s) in ${words.length} words`);
  }

  // Urgency language
  URGENCY_PHRASES.forEach((phrase) => {
    if (lower.includes(phrase)) {
      phishingScore += 10;
      addFlag("medium", "urgency", `⏰ Urgency tactic: "${phrase}"`);
    }
  });

  // Personal info requests
  PERSONAL_INFO_PATTERNS.forEach(({ pattern, label }) => {
    if (pattern.test(text)) {
      phishingScore += 25;
      addFlag("high", "personal_info", `🔐 Request for sensitive data: ${label}`);
    }
  });

  // Spoofing cues
  SPOOFING_CUES.forEach((cue) => {
    if (lower.includes(cue.toLowerCase())) {
      phishingScore += 15;
      addFlag("high", "spoofing", `🎭 Potential sender spoofing: "${cue}"`);
    }
  });

  // ALL CAPS words
  const rawWords = text.split(/\s+/);
  const capsWords = rawWords.filter((w) => w.length > 3 && w === w.toUpperCase() && /[A-Z]/.test(w));
  if (capsWords.length >= 3) {
    phishingScore += 8;
    addFlag("low", "style", `📢 Excessive CAPS usage (${capsWords.length} all-caps words: ${capsWords.slice(0,4).join(", ")})`);
  }

  // Excessive exclamation marks
  const exclamations = (text.match(/!/g) || []).length;
  if (exclamations >= 3) {
    phishingScore += 8;
    addFlag("medium", "style", `❗ Excessive exclamation marks (${exclamations} found)`);
  }

  // Mixed-script / homoglyph detection (Cyrillic/Greek chars masquerading as Latin)
  if (/[\u0400-\u04FF\u0370-\u03FF]/.test(text)) {
    phishingScore += 20;
    addFlag("high", "spoofing", `⚠️ Non-Latin characters detected — possible homoglyph attack`);
  }

  // ── Fake News checks ──────────────────────────────────────────────────────

  FAKE_NEWS_KEYWORDS.forEach((kw) => {
    if (lower.includes(kw)) {
      fakeNewsScore += 14;
      addFlag("high", "fake_news", `📰 Misinformation indicator: "${kw}"`);
    }
  });

  SENSATIONAL_WORDS.forEach((word) => {
    if (new RegExp(`\\b${word}\\b`, "i").test(text)) {
      fakeNewsScore += 5;
      addFlag("low", "sensational", `🔥 Sensational language: "${word}"`);
    }
  });

  // Clickbait patterns
  CLICKBAIT_PATTERNS.forEach((pattern) => {
    const m = text.match(pattern);
    if (m) {
      fakeNewsScore += 12;
      addFlag("medium", "clickbait", `🖱️ Clickbait pattern: "${m[0].substring(0, 60)}"`);
    }
  });

  // Unreliable source domains
  UNRELIABLE_SOURCE_PATTERNS.forEach((pattern) => {
    if (pattern.test(text)) {
      fakeNewsScore += 35;
      addFlag("high", "source", `🌐 Known unreliable/satire source detected`);
    }
  });

  // Conspiracy-style vague "they" framing
  const theyCount = (lower.match(/\bthey\b|\bthem\b|\bthose people\b/g) || []).length;
  if (theyCount >= 4) {
    fakeNewsScore += 10;
    addFlag("medium", "framing", `👥 Vague conspiratorial framing: "they/them" used ${theyCount} times without attribution`);
  }

  // Emotional viral-sharing manipulation
  const emotionalTriggers = [
    "you need to know", "spread the word", "share with everyone",
    "tell everyone", "pass it on", "before they delete",
    "if you care about", "only real patriots", "every american should",
    "wake up before it's too late",
  ];
  emotionalTriggers.forEach((trigger) => {
    if (lower.includes(trigger)) {
      fakeNewsScore += 12;
      addFlag("medium", "manipulation", `💬 Emotional manipulation: "${trigger}"`);
    }
  });

  // Absolute / unverifiable claims
  const absoluteClaims = [
    "100% proven", "scientifically proven", "guaranteed", "always works",
    "never fails", "100% effective", "zero side effects", "completely safe",
    "the only cure", "instant results",
  ];
  absoluteClaims.forEach((claim) => {
    if (lower.includes(claim)) {
      fakeNewsScore += 10;
      addFlag("medium", "fake_news", `📊 Unverifiable absolute claim: "${claim}"`);
    }
  });

  // ── Readability analysis ──────────────────────────────────────────────────
  const readability = analyzeReadability(text);

  // Very low reading ease may indicate deliberately confusing / obfuscated text
  if (readability.readingEase < 20) {
    phishingScore += 5;
    addFlag("low", "style", `📖 Very low readability score (${readability.readingEase}) — unusually complex language`);
  }

  // ── Determine dominant type ───────────────────────────────────────────────
  const totalScore = Math.max(phishingScore, fakeNewsScore);
  const normalizedScore = Math.min(100, totalScore);
  const type = phishingScore >= fakeNewsScore ? "phishing" : "fake_news";

  let confidence, summary, recommendations;

  if (normalizedScore >= 70) {
    confidence = "HIGH";
    if (type === "phishing") {
      summary = "This message shows strong indicators of a phishing attack. It is designed to steal your personal information or credentials.";
      recommendations = [
        "Do NOT click any links in this message.",
        "Do NOT provide any personal, financial, or login information.",
        "Report this message to your email provider as phishing.",
        "If you already clicked a link, change your passwords immediately.",
        "Verify the sender directly through official channels (not reply).",
        "Enable two-factor authentication on all important accounts.",
      ];
    } else {
      summary = "This content shows strong indicators of misinformation or fake news designed to mislead or manipulate readers.";
      recommendations = [
        "Do NOT share this content without verifying it first.",
        "Cross-check with trusted fact-checking sites: Snopes, FactCheck.org, PolitiFact.",
        "Search for corroborating reports from established news outlets.",
        "Be skeptical of content that triggers strong emotional reactions.",
        "Check if the source domain is known for satire or misinformation.",
        "Look for named sources, citations, and verifiable evidence.",
      ];
    }
  } else if (normalizedScore >= 35) {
    confidence = "MEDIUM";
    if (type === "phishing") {
      summary = "This message has several suspicious characteristics typical of phishing attempts. Proceed with extreme caution.";
      recommendations = [
        "Avoid clicking links — navigate to websites directly instead.",
        "Verify the sender's email address carefully for spoofing.",
        "Contact the organization directly via their official website.",
        "Do not download any attachments from this message.",
        "Check if the urgency is artificial (a common social engineering tactic).",
      ];
    } else {
      summary = "This content contains several red flags associated with misleading or sensationalized news. Fact-check before sharing.";
      recommendations = [
        "Search for the story on reputable news platforms before sharing.",
        "Be wary of extreme emotional language and lack of attributed sources.",
        "Check the publication date — old stories are often re-shared deceptively.",
        "Use reverse image search to verify photos in the article.",
        "Look for an 'About' page on the source website.",
      ];
    }
  } else if (normalizedScore >= 10) {
    confidence = "LOW";
    summary = type === "phishing"
      ? "A few minor suspicious signals were detected but nothing conclusive. Exercise general caution."
      : "A few sensational elements were found but content may still be legitimate. Verify from trusted sources.";
    recommendations = [
      "Exercise general caution and verify before acting.",
      "Check the original source of the content.",
    ];
  } else {
    confidence = "NONE";
    summary = "No significant indicators of phishing or fake news were detected. The content appears to be relatively safe.";
    recommendations = ["No specific actions required. Continue practicing general online safety."];
  }

  // Deduplicate and sort flags: high → medium → low
  const severityOrder = { high: 0, medium: 1, low: 2 };
  const seen = new Set();
  const uniqueFlags = flagObjects
    .filter((f) => {
      if (seen.has(f.message)) return false;
      seen.add(f.message);
      return true;
    })
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Category breakdown counts
  const categoryCounts = uniqueFlags.reduce((acc, f) => {
    acc[f.category] = (acc[f.category] || 0) + 1;
    return acc;
  }, {});

  return {
    type: normalizedScore < 10 ? "safe" : type,
    score: normalizedScore,
    phishingScore: Math.min(100, phishingScore),
    fakeNewsScore: Math.min(100, fakeNewsScore),
    confidence,
    flags: uniqueFlags,          // Array of { severity, category, message }
    summary,
    recommendations,
    readability,
    urlsFound: urls,
    wordCount: words.length,
    flagCount: uniqueFlags.length,
    categoryCounts,
    analyzedAt: new Date().toISOString(),
  };
}

// ─── Export ───────────────────────────────────────────────────────────────────
window.Detector = { analyzeText };
