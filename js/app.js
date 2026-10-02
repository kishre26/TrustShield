/**
 * TrustShield — Fake News & Phishing Message Detector
 * UI Controller v2.0
 */

(function () {
  // ─── DOM References ─────────────────────────────────────────────────────
  const inputText          = document.getElementById("input-text");
  const analyzeBtn         = document.getElementById("analyze-btn");
  const clearBtn           = document.getElementById("clear-btn");
  const charCount          = document.getElementById("char-count");
  const resultSection      = document.getElementById("result-section");
  const placeholderSection = document.getElementById("placeholder-section");
  const exampleBtns        = document.querySelectorAll(".example-btn");

  // Verdict
  const verdictBadge   = document.getElementById("verdict-badge");
  const verdictTitle   = document.getElementById("verdict-title");
  const verdictSummary = document.getElementById("verdict-summary");
  const analyzedTime   = document.getElementById("analyzed-time");

  // Score
  const scoreBar      = document.getElementById("score-bar");
  const scoreValue    = document.getElementById("score-value");
  const phishBarFill  = document.getElementById("phish-bar-fill");
  const phishScoreVal = document.getElementById("phish-score-val");
  const fakeBarFill   = document.getElementById("fake-bar-fill");
  const fakeScoreVal  = document.getElementById("fake-score-val");

  // Flags / tabs
  const tabBtns       = document.querySelectorAll(".tab-btn");
  const flagsList     = document.getElementById("flags-list");
  const flagsEmpty    = document.getElementById("flags-empty");
  const flagsCount    = document.getElementById("flags-count");

  // Readability
  const rdWordCount   = document.getElementById("rd-word-count");
  const rdSentences   = document.getElementById("rd-sentences");
  const rdAvgWords    = document.getElementById("rd-avg-words");
  const rdGrade       = document.getElementById("rd-grade");
  const rdEase        = document.getElementById("rd-ease");
  const rdLevel       = document.getElementById("rd-level");
  const rdUrlCount    = document.getElementById("rd-url-count");

  // Stats
  const statsWordCount  = document.getElementById("stats-word-count");
  const statsFlagCount  = document.getElementById("stats-flag-count");
  const statsConfidence = document.getElementById("stats-confidence");

  // Recommendations
  const recList       = document.getElementById("rec-list");

  // Actions
  const copyReportBtn = document.getElementById("copy-report-btn");

  // History
  const historyList   = document.getElementById("history-list");
  const historyEmpty  = document.getElementById("history-empty");
  const clearHistBtn  = document.getElementById("clear-history-btn");

  // ─── Example Texts ──────────────────────────────────────────────────────
  const examples = {
    phishing: `URGENT: Your PayPal account has been suspended due to unusual activity detected. You must verify your account immediately or it will be permanently closed within 24 hours. Click the link below to confirm your identity and update your payment details: http://192.168.1.1/paypa1-secure-verify.tk\n\nDear Account Holder, please enter your password and credit card number to restore access. ACT NOW before it's too late! FAILURE TO RESPOND will result in permanent termination of your account.`,

    fakenews: `SHOCKING TRUTH: What mainstream media won't tell you! Bill Gates is using 5G networks to spread a secret microchip through vaccines. Doctors hate this one simple trick that BIG PHARMA has been suppressing for years! The deep state is HIDING THIS from you. Share before it's deleted!! They don't want you to know the REAL truth. Wake up sheeple — the government is covering this up. SHARE WITH EVERYONE before they remove this post! This video will shock you. 100% proven by secret whistleblowers! Every patriot should see this before it's censored by mainstream media.`,

    safe: `The local city council announced that road maintenance work on Main Street will begin next Monday and is expected to last approximately two weeks. Residents are advised to use alternate routes during this period. The project involves repaving three blocks and replacing aging water pipes. Estimated cost is $1.2 million, funded by the municipal infrastructure budget. For more information, visit the official city website or contact the public works department at (555) 123-4567.`,
  };

  // ─── History (localStorage) ─────────────────────────────────────────────
  const HISTORY_KEY = "trustshield_history";
  const MAX_HISTORY = 6;

  function loadHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; }
    catch { return []; }
  }

  function saveHistory(entry) {
    const hist = loadHistory();
    hist.unshift(entry);
    if (hist.length > MAX_HISTORY) hist.pop();
    localStorage.setItem(HISTORY_KEY, JSON.stringify(hist));
    renderHistory();
  }

  function renderHistory() {
    const hist = loadHistory();
    historyList.innerHTML = "";
    if (hist.length === 0) {
      historyEmpty.style.display = "block";
      return;
    }
    historyEmpty.style.display = "none";
    hist.forEach((h, i) => {
      const item = document.createElement("div");
      item.className = "history-item";
      const typeIcon = h.type === "safe" ? "✅" : h.type === "phishing" ? "🎣" : "📰";
      const typeLabel = h.type === "safe" ? "Safe" : h.type === "phishing" ? "Phishing" : "Fake News";
      const scoreClass = h.score >= 70 ? "high" : h.score >= 35 ? "medium" : "low";
      const date = new Date(h.analyzedAt);
      const timeStr = date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const dateStr = date.toLocaleDateString([], { month: "short", day: "numeric" });

      item.innerHTML = `
        <div class="hist-header">
          <span class="hist-type-badge ${h.type}">${typeIcon} ${typeLabel}</span>
          <span class="hist-score score-${scoreClass}">${h.score}/100</span>
        </div>
        <div class="hist-preview">${h.preview}</div>
        <div class="hist-meta">${dateStr} at ${timeStr} · ${h.wordCount} words · ${h.flagCount} signal${h.flagCount !== 1 ? "s" : ""}</div>
      `;
      item.addEventListener("click", () => {
        inputText.value = h.fullText;
        charCount.textContent = `${h.fullText.length} characters`;
        analyzeBtn.disabled = false;
        runAnalysis();
        inputText.scrollIntoView({ behavior: "smooth" });
      });
      historyList.appendChild(item);
    });
  }

  // ─── Tab State ───────────────────────────────────────────────────────────
  let currentTab = "all";
  let currentFlags = [];

  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      currentTab = btn.dataset.tab;
      renderFlags(currentFlags, currentTab);
    });
  });

  function renderFlags(flags, tab) {
    flagsList.innerHTML = "";
    const filtered = tab === "all" ? flags : flags.filter((f) => f.category === tab || f.severity === tab);

    if (filtered.length === 0) {
      flagsEmpty.style.display = "block";
      flagsCount.textContent = "0 signals";
    } else {
      flagsEmpty.style.display = "none";
      flagsCount.textContent = `${filtered.length} signal${filtered.length !== 1 ? "s" : ""}`;
      filtered.forEach((flag) => {
        const li = document.createElement("li");
        li.className = `flag-item severity-${flag.severity}`;
        const severityDot = `<span class="sev-dot sev-${flag.severity}"></span>`;
        li.innerHTML = `${severityDot}<span>${flag.message}</span>`;
        flagsList.appendChild(li);
      });
    }
  }

  // ─── Event Listeners ────────────────────────────────────────────────────

  inputText.addEventListener("input", () => {
    const len = inputText.value.length;
    charCount.textContent = `${len} character${len !== 1 ? "s" : ""}`;
    analyzeBtn.disabled = inputText.value.trim().length < 10;
  });

  analyzeBtn.addEventListener("click", runAnalysis);

  clearBtn.addEventListener("click", () => {
    inputText.value = "";
    charCount.textContent = "0 characters";
    analyzeBtn.disabled = true;
    placeholderSection.style.display = "flex";
    resultSection.style.display = "none";
  });

  exampleBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      inputText.value = examples[btn.dataset.type];
      charCount.textContent = `${inputText.value.length} characters`;
      analyzeBtn.disabled = false;
      runAnalysis();
    });
  });

  copyReportBtn && copyReportBtn.addEventListener("click", () => {
    const text = buildReportText(window._lastResult, inputText.value);
    navigator.clipboard.writeText(text).then(() => {
      copyReportBtn.textContent = "✅ Copied!";
      setTimeout(() => { copyReportBtn.textContent = "📋 Copy Report"; }, 2000);
    }).catch(() => {
      copyReportBtn.textContent = "❌ Failed";
      setTimeout(() => { copyReportBtn.textContent = "📋 Copy Report"; }, 2000);
    });
  });

  clearHistBtn && clearHistBtn.addEventListener("click", () => {
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
  });

  // Accordion toggles
  document.querySelectorAll(".accordion-header").forEach((header) => {
    header.addEventListener("click", () => {
      const item = header.closest(".accordion-item");
      item.classList.toggle("open");
    });
  });

  // ─── Analysis Runner ────────────────────────────────────────────────────

  function runAnalysis() {
    const text = inputText.value.trim();
    if (text.length < 10) return;

    analyzeBtn.classList.add("scanning");
    analyzeBtn.textContent = "Analyzing…";
    analyzeBtn.disabled = true;

    setTimeout(() => {
      const result = window.Detector.analyzeText(text);
      window._lastResult = result;
      renderResult(result, text);
      saveHistory({
        type: result.type,
        score: result.score,
        confidence: result.confidence,
        wordCount: result.wordCount,
        flagCount: result.flagCount,
        preview: text.substring(0, 80).replace(/\n/g, " ") + (text.length > 80 ? "…" : ""),
        fullText: text,
        analyzedAt: result.analyzedAt,
      });
      analyzeBtn.classList.remove("scanning");
      analyzeBtn.textContent = "🔍 Analyze";
      analyzeBtn.disabled = false;
    }, 750);
  }

  // ─── Render Result ───────────────────────────────────────────────────────

  function renderResult(r, rawText) {
    placeholderSection.style.display = "none";
    resultSection.style.display = "block";
    resultSection.scrollIntoView({ behavior: "smooth", block: "start" });

    // Timestamp
    if (analyzedTime) {
      const d = new Date(r.analyzedAt);
      analyzedTime.textContent = `Analyzed at ${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
    }

    // ── Verdict ──────────────────────────────────────────────────────────
    verdictBadge.className = "verdict-badge";

    if (r.type === "safe") {
      verdictBadge.classList.add("safe");
      verdictBadge.textContent = "✅ Safe";
      verdictTitle.textContent = "No Threats Detected";
    } else if (r.type === "phishing") {
      const level = r.confidence === "HIGH" ? "danger" : r.confidence === "MEDIUM" ? "warning" : "caution";
      verdictBadge.classList.add(level);
      verdictBadge.textContent = r.confidence === "HIGH" ? "🚨 Phishing" : r.confidence === "MEDIUM" ? "⚠️ Likely Phishing" : "🔍 Possible Phishing";
      verdictTitle.textContent = r.confidence === "HIGH" ? "High-Risk Phishing Message" : r.confidence === "MEDIUM" ? "Suspected Phishing Attempt" : "Minor Phishing Signals";
    } else {
      const level = r.confidence === "HIGH" ? "danger" : r.confidence === "MEDIUM" ? "warning" : "caution";
      verdictBadge.classList.add(level);
      verdictBadge.textContent = r.confidence === "HIGH" ? "🗞️ Fake News" : r.confidence === "MEDIUM" ? "⚠️ Likely Misleading" : "🔍 Possibly Misleading";
      verdictTitle.textContent = r.confidence === "HIGH" ? "High-Risk Misinformation" : r.confidence === "MEDIUM" ? "Suspected Fake News / Misinformation" : "Minor Misinformation Signals";
    }
    verdictSummary.textContent = r.summary;

    // ── Score bar ─────────────────────────────────────────────────────────
    animateBar(scoreBar, r.score);
    scoreValue.textContent = r.score;
    scoreBar.className = "score-bar-fill";
    scoreBar.classList.add(r.score >= 70 ? "high" : r.score >= 35 ? "medium" : "low");

    animateBar(phishBarFill, r.phishingScore);
    phishScoreVal.textContent = r.phishingScore;
    animateBar(fakeBarFill, r.fakeNewsScore);
    fakeScoreVal.textContent = r.fakeNewsScore;

    // ── Flags (reset to "all" tab) ────────────────────────────────────────
    currentFlags = r.flags;
    currentTab = "all";
    tabBtns.forEach((b) => b.classList.toggle("active", b.dataset.tab === "all"));
    renderFlags(r.flags, "all");

    // ── Readability stats ─────────────────────────────────────────────────
    const rd = r.readability;
    if (rdWordCount)  rdWordCount.textContent  = r.wordCount;
    if (rdSentences)  rdSentences.textContent  = rd.sentenceCount;
    if (rdAvgWords)   rdAvgWords.textContent   = rd.avgWordsPerSentence;
    if (rdGrade)      rdGrade.textContent      = rd.fkGrade;
    if (rdEase)       rdEase.textContent       = rd.readingEase + "%";
    if (rdLevel)      rdLevel.textContent      = rd.readingLevel;
    if (rdUrlCount)   rdUrlCount.textContent   = r.urlsFound.length;

    // ── Summary stats ─────────────────────────────────────────────────────
    statsWordCount.textContent = r.wordCount;
    statsFlagCount.textContent = r.flagCount;
    statsConfidence.textContent = r.confidence;
    statsConfidence.className = "stat-value confidence-" + r.confidence.toLowerCase();

    // ── Recommendations ───────────────────────────────────────────────────
    recList.innerHTML = "";
    (r.recommendations || []).forEach((rec) => {
      const li = document.createElement("li");
      li.className = "rec-item";
      li.textContent = rec;
      recList.appendChild(li);
    });

    // ── URL breakdown (if any) ────────────────────────────────────────────
    const urlPanel = document.getElementById("url-panel");
    const urlListEl = document.getElementById("url-breakdown-list");
    if (urlPanel && urlListEl) {
      if (r.urlsFound.length === 0) {
        urlPanel.style.display = "none";
      } else {
        urlPanel.style.display = "block";
        urlListEl.innerHTML = "";
        r.urlsFound.forEach((url) => {
          const issues = window.Detector._classifyURL ? window.Detector._classifyURL(url) : [];
          const li = document.createElement("li");
          li.className = "url-item";
          const safe = issues.length === 0;
          li.innerHTML = `
            <span class="url-icon">${safe ? "🟢" : "🔴"}</span>
            <span class="url-text">${url.substring(0, 70)}${url.length > 70 ? "…" : ""}</span>
            ${issues.length ? `<span class="url-issues">${issues.join(", ")}</span>` : '<span class="url-clean">No issues detected</span>'}
          `;
          urlListEl.appendChild(li);
        });
      }
    }
  }

  // ─── Report Builder ──────────────────────────────────────────────────────

  function buildReportText(r, text) {
    if (!r) return "";
    const line = "─".repeat(50);
    const d = new Date(r.analyzedAt).toLocaleString();
    const typeLabel = r.type === "safe" ? "SAFE" : r.type === "phishing" ? "PHISHING" : "FAKE NEWS / MISINFORMATION";
    let out = `TRUSTSHIELD ANALYSIS REPORT\n${line}\n`;
    out += `Date/Time : ${d}\n`;
    out += `Verdict   : ${typeLabel}\n`;
    out += `Risk Score: ${r.score}/100  (Confidence: ${r.confidence})\n`;
    out += `Phishing  : ${r.phishingScore}/100  |  Fake News: ${r.fakeNewsScore}/100\n`;
    out += `${line}\nSUMMARY\n${r.summary}\n`;
    out += `${line}\nDETECTED SIGNALS (${r.flagCount})\n`;
    r.flags.forEach((f, i) => {
      out += `${i + 1}. [${f.severity.toUpperCase()}] ${f.message}\n`;
    });
    out += `${line}\nRECOMMENDATIONS\n`;
    (r.recommendations || []).forEach((rec, i) => { out += `${i + 1}. ${rec}\n`; });
    out += `${line}\nREADABILITY\n`;
    out += `Words: ${r.wordCount} | Sentences: ${r.readability.sentenceCount} | Avg words/sentence: ${r.readability.avgWordsPerSentence}\n`;
    out += `Reading Level: ${r.readability.readingLevel} (FK Grade: ${r.readability.fkGrade})\n`;
    if (r.urlsFound.length) {
      out += `${line}\nURLs FOUND (${r.urlsFound.length})\n`;
      r.urlsFound.forEach((u, i) => { out += `${i + 1}. ${u}\n`; });
    }
    out += `${line}\nANALYZED TEXT (first 300 chars)\n${text.substring(0, 300)}${text.length > 300 ? "…" : ""}\n`;
    out += `${line}\nGenerated by TrustShield Detector\n`;
    return out;
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────

  function animateBar(el, targetPct) {
    el.style.width = "0%";
    requestAnimationFrame(() => requestAnimationFrame(() => {
      el.style.width = targetPct + "%";
    }));
  }

  // ─── Init ────────────────────────────────────────────────────────────────
  renderHistory();
})();
