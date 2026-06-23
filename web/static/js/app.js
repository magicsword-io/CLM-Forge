// ============================================================================
// CLM Forge UI — supports single-file and batch (multi-file) analysis
// ============================================================================

const editor = document.getElementById('code-editor');
const lineNumbers = document.getElementById('line-numbers');
const fileInput = document.getElementById('file-input');
const fileInput2 = document.getElementById('file-input-2');
const analyzeBtn = document.getElementById('analyze-btn');
const clearBtn = document.getElementById('clear-btn');
const findingsList = document.getElementById('findings-list');
const summaryBar = document.getElementById('summary-bar');
const filenameDisplay = document.getElementById('filename-display');
const lineCount = document.getElementById('line-count');
const filterChips = document.getElementById('filter-chips');
const singleMode = document.getElementById('single-mode');
const batchMode = document.getElementById('batch-mode');
const batchFileStrip = document.getElementById('batch-file-strip');
const batchSummary = document.getElementById('batch-summary');
const batchFindingsList = document.getElementById('batch-findings-list');
const batchExportBar = document.getElementById('batch-export-bar');
const batchBackBtn = document.getElementById('batch-back-btn');
const failOnSelect = document.getElementById('fail-on-select');

// State
let currentFilename = 'script.ps1';
let currentFindings = [];
let activeFilter = 'all';
let lastAnalysisResult = null;
// Batch
let batchScripts = [];         // [{filename, content}]
let lastBatchResult = null;    // {scripts: [...], aggregate: {...}}
let failOn = '';
let focusedBatchIdx = -1;      // when >=0, user is viewing one batch script in the split view

const SEVERITY_ORDER = {Critical: 0, High: 1, Medium: 2, Low: 3};

// ============================================================================
// SINGLE-FILE MODE
// ============================================================================

function updateLineNumbers() {
  const lines = editor.value.split('\n').length;
  lineNumbers.innerHTML = Array.from({length: lines}, (_, i) =>
    `<div id="ln-${i+1}">${i + 1}</div>`
  ).join('');
  lineCount.textContent = `${lines} lines`;
  analyzeBtn.disabled = !editor.value.trim() && batchScripts.length === 0;
}

editor.addEventListener('input', () => {
  // If user types in editor, drop batch state
  if (batchScripts.length > 0) enterSingleMode();
  updateLineNumbers();
});
editor.addEventListener('scroll', () => { lineNumbers.scrollTop = editor.scrollTop; });
updateLineNumbers();

// File input handling (both inputs behave the same)
function handleFileList(files) {
  const fs = Array.from(files || []);
  if (fs.length === 0) return;

  if (fs.length === 1 && batchScripts.length === 0) {
    // Single-file flow (preserve legacy behavior)
    const file = fs[0];
    currentFilename = file.name;
    filenameDisplay.textContent = file.name;
    const reader = new FileReader();
    reader.onload = (ev) => { editor.value = ev.target.result; updateLineNumbers(); };
    reader.readAsText(file);
    return;
  }

  // Multi-file → batch mode
  const readers = fs.map(file => new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = (ev) => resolve({filename: file.name, content: ev.target.result});
    r.onerror = () => reject(new Error(`Failed to read ${file.name}`));
    r.readAsText(file);
  }));
  Promise.all(readers).then(list => {
    // merge (skip duplicates by filename)
    const existing = new Set(batchScripts.map(s => s.filename));
    list.forEach(s => { if (!existing.has(s.filename)) batchScripts.push(s); });
    enterBatchMode();
  }).catch(err => alert('File load error: ' + err.message));
}

fileInput.addEventListener('change', (e) => { handleFileList(e.target.files); e.target.value = ''; });
fileInput2.addEventListener('change', (e) => { handleFileList(e.target.files); e.target.value = ''; });

// Clear
clearBtn.addEventListener('click', () => {
  editor.value = '';
  currentFindings = [];
  lastAnalysisResult = null;
  activeFilter = 'all';
  batchScripts = [];
  lastBatchResult = null;
  enterSingleMode();
  updateLineNumbers();
  filenameDisplay.textContent = 'Paste or upload one or more PowerShell scripts';
  summaryBar.style.display = 'none';
  document.getElementById('export-bar').style.display = 'none';
  filterChips.innerHTML = '';
  findingsList.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">&#128269;</div>
      <p>Upload or paste a PowerShell script and click <strong>Analyze</strong>.</p>
      <p class="meta">Find what WDAC Script Enforcement blocks, then fix or allow with intent.</p>
    </div>`;
  document.querySelectorAll('.highlight-line').forEach(el => el.classList.remove('highlight-line'));
});

batchBackBtn.addEventListener('click', () => {
  batchScripts = [];
  lastBatchResult = null;
  enterSingleMode();
  updateLineNumbers();
});

// Analyze (dispatch based on mode)
analyzeBtn.addEventListener('click', async () => {
  if (batchScripts.length > 0) {
    await runBatchAnalysis();
  } else {
    await runSingleAnalysis();
  }
});

async function runSingleAnalysis() {
  const content = editor.value.trim();
  if (!content) return;
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = 'Analyzing...';
  try {
    const resp = await fetch('/api/analyze-text', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({content, filename: currentFilename}),
    });
    if (!resp.ok) throw new Error((await resp.json()).detail || 'Analysis failed');
    const result = await resp.json();
    lastAnalysisResult = result;
    currentFindings = result.findings || [];
    renderSummary(result.summary, result.analysis_method);
    renderFilters();
    renderFindings();
    renderWDACHash(result.wdac_hash);
    renderCLMDynamic(result.clm_dynamic_results, result.analysis_method);
    document.getElementById('export-bar').style.display = 'flex';
  } catch (err) {
    findingsList.innerHTML = `<div class="empty-state"><p style="color:var(--ms-red)">Error: ${esc(err.message)}</p></div>`;
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'Analyze';
  }
}

function renderSummary(summary, method) {
  const methodLabel = formatMethodLabel(method);
  if (!summary || summary.total_findings === 0) {
    summaryBar.style.display = 'flex';
    summaryBar.innerHTML = `
      <div class="summary-item"><span class="summary-dot pass"></span> No CLM blockers detected for this script.</div>
      <div class="summary-item">${methodLabel}</div>`;
    return;
  }
  summaryBar.style.display = 'flex';
  summaryBar.innerHTML = `
    <div class="summary-item"><strong>${summary.total_findings}</strong>&nbsp;finding${summary.total_findings !== 1 ? 's' : ''}</div>
    ${summary.Critical ? `<div class="summary-item"><span class="summary-dot critical"></span> ${summary.Critical} Critical</div>` : ''}
    ${summary.High ? `<div class="summary-item"><span class="summary-dot high"></span> ${summary.High} High</div>` : ''}
    ${summary.Medium ? `<div class="summary-item"><span class="summary-dot medium"></span> ${summary.Medium} Medium</div>` : ''}
    ${summary.Low ? `<div class="summary-item"><span class="summary-dot low"></span> ${summary.Low} Low</div>` : ''}
    <div class="summary-item">${methodLabel}</div>`;
}

function formatMethodLabel(method) {
  if (!method) return '<span class="method-badge method-static">static only</span>';
  const parts = method.split(' + ');
  if (parts.includes('constrained_runspace')) return '<span class="method-badge method-dynamic">static + dynamic CLM</span>';
  if (parts.includes('powershell_ast')) return '<span class="method-badge method-ps">static + PowerShell AST</span>';
  return '<span class="method-badge method-static">static analysis</span>';
}

function renderWDACHash(hashInfo) {
  if (!hashInfo || !hashInfo.sha256) return;
  const hash = normalizeSha256(hashInfo.sha256);
  if (!hash) return;
  const section = document.createElement('div');
  section.className = 'wdac-hash-section';
  section.innerHTML = `
    <div class="wdac-hash-box">
      <div class="wdac-hash-title">WDAC SHA256 Hash</div>
      <div class="wdac-hash-instruction">${esc(hashInfo.instruction)}</div>
      <div class="wdac-hash-value js-copy-hash" data-copy-text="${hash}" title="Click to copy">
        ${hash}
        <span class="copy-hint">click to copy</span>
      </div>
    </div>`;
  findingsList.appendChild(section);
}

function renderCLMDynamic(clmResults, analysisMethod) {
  const ranDynamic = analysisMethod && analysisMethod.includes('constrained_runspace');
  if (!ranDynamic && (!clmResults || !clmResults.errors || clmResults.errors.length === 0)) return;

  const section = document.createElement('div');
  const hasErrors = clmResults && clmResults.errors && clmResults.errors.length > 0;
  const blocked = clmResults ? (clmResults.blockedByCLM || 0) : 0;
  const other = clmResults ? (clmResults.otherErrors || 0) : 0;
  const windowsOnlyRules = ['CLM004','CLM005','CLM008','CLM010','CLM016','CLM018','CLM019','CLM025','CLM031'];
  const missedByDynamic = currentFindings.filter(f => windowsOnlyRules.includes(f.rule_id));
  const hasGap = !hasErrors && missedByDynamic.length > 0;

  if (!hasErrors) {
    section.className = 'clm-dynamic-section clm-dynamic-pass';
    section.innerHTML = `
      <div class="clm-dynamic-header clm-pass-header">
        <span><strong>&#10003; Dynamic CLM Test Passed</strong> &mdash; Executed in a Linux ConstrainedLanguage runspace</span>
        <span class="clm-pass-badge">0 errors</span>
      </div>
      ${hasGap ? `
      <div class="clm-gap-warning">
        <strong>&#9888; Platform gap:</strong> ${missedByDynamic.length} static finding${missedByDynamic.length !== 1 ? 's' : ''} flagged above would be blocked by <strong>Windows WDAC CLM</strong> but passed here because Linux constrained runspace is more permissive.
        <ul>${missedByDynamic.map(f => `<li><strong>${esc(f.rule_id)}</strong>: ${esc(f.rule_name)} (line ${f.line})</li>`).join('')}</ul>
        <span class="clm-gap-tip">Trust the static analysis for Windows WDAC deployment decisions.</span>
      </div>` : `<div class="clm-pass-body">No restrictions triggered. This script runs cleanly under Constrained Language Mode.</div>`}`;
  } else {
    section.className = 'clm-dynamic-section';
    section.innerHTML = `
      <div class="clm-dynamic-header">
        <strong>Dynamic CLM Test</strong> &mdash; Executed in a Linux ConstrainedLanguage runspace
        <span class="meta">${blocked} blocked by CLM, ${other} other errors</span>
      </div>
      ${clmResults.errors.map(e => `
        <div class="finding-card ${e.blocked ? 'severity-critical' : 'severity-low'}">
          <div class="finding-header" style="cursor:default">
            <div class="finding-title">
              <span class="badge ${e.blocked ? 'critical' : 'low'}">${e.blocked ? 'CLM BLOCKED' : 'Error'}</span>
              <span>${esc(e.error).substring(0, 120)}</span>
            </div>
            ${e.line ? `<span class="line-badge">Line ${e.line}</span>` : ''}
          </div>
          ${e.codeSnippet ? `<div style="padding:0 14px 10px"><div class="finding-code">${esc(e.codeSnippet)}</div></div>` : ''}
        </div>`).join('')}
      ${missedByDynamic.length > 0 ? `
      <div class="clm-gap-warning">
        <strong>&#9888; Platform gap:</strong> ${missedByDynamic.length} additional static finding${missedByDynamic.length !== 1 ? 's' : ''} would also be blocked by <strong>Windows WDAC CLM</strong> but passed on Linux:
        <ul>${missedByDynamic.map(f => `<li><strong>${esc(f.rule_id)}</strong>: ${esc(f.rule_name)} (line ${f.line})</li>`).join('')}</ul>
      </div>` : ''}`;
  }
  findingsList.appendChild(section);
}

function renderFilters() {
  filterChips.innerHTML = '';
  const severities = ['all', 'Critical', 'High', 'Medium', 'Low'];
  severities.forEach(sev => {
    const count = sev === 'all' ? currentFindings.length : currentFindings.filter(f => f.severity === sev).length;
    if (sev !== 'all' && count === 0) return;
    const chip = document.createElement('button');
    chip.className = `chip${activeFilter === sev ? ' active' : ''}`;
    chip.textContent = sev === 'all' ? `All (${count})` : `${sev} (${count})`;
    chip.onclick = () => { activeFilter = sev; renderFilters(); renderFindings(); };
    filterChips.appendChild(chip);
  });
}

function renderFindings() {
  const filtered = activeFilter === 'all' ? currentFindings : currentFindings.filter(f => f.severity === activeFilter);
  if (filtered.length === 0 && currentFindings.length === 0) {
    findingsList.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon" style="color:var(--ms-green)">&#10003;</div>
        <p><strong>No CLM compatibility issues detected.</strong></p>
        <p class="meta">This script is ready for stricter WDAC script enforcement rollout.</p>
      </div>`;
    return;
  }
  if (filtered.length === 0) {
    findingsList.innerHTML = `<div class="empty-state"><p>No findings match the selected filter.</p></div>`;
    return;
  }
  filtered.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4) || a.line - b.line);
  findingsList.innerHTML = filtered.map((f, i) => `
    <div class="finding-card severity-${f.severity.toLowerCase()}" id="finding-${i}">
      <div class="finding-header" onclick="toggleFinding(${i})">
        <div class="finding-title">
          <span class="badge ${f.severity.toLowerCase()}">${esc(f.severity)}</span>
          <span>${esc(f.rule_id)}: ${esc(f.rule_name)}</span>
        </div>
        <div class="finding-meta">
          <span class="line-badge" onclick="event.stopPropagation();scrollToLine(${f.line})">Line ${f.line}</span>
        </div>
      </div>
      <div class="finding-body">
        ${buildFindingDetailsHtml(f)}
      </div>
    </div>`).join('');
}

function toggleFinding(i) {
  const card = document.getElementById(`finding-${i}`);
  card.classList.toggle('expanded');
  if (card.classList.contains('expanded') && currentFindings[i]) scrollToLine(currentFindings[i].line);
}

function scrollToLine(lineNum) {
  const lines = editor.value.split('\n');
  let charPos = 0;
  for (let i = 0; i < lineNum - 1 && i < lines.length; i++) charPos += lines[i].length + 1;
  editor.focus();
  editor.setSelectionRange(charPos, charPos + (lines[lineNum - 1] || '').length);
  const computed = window.getComputedStyle(editor);
  const lineHeight = parseFloat(computed.lineHeight) || parseFloat(computed.fontSize) * 1.5;
  editor.scrollTop = Math.max(0, (lineNum - 5) * lineHeight);
  lineNumbers.scrollTop = editor.scrollTop;
  document.querySelectorAll('.highlight-line').forEach(el => el.classList.remove('highlight-line'));
  const lnEl = document.getElementById(`ln-${lineNum}`);
  if (lnEl) lnEl.classList.add('highlight-line');
}

function esc(s) {
  if (s == null) return '';
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

function buildFindingDetailsHtml(f) {
  return `
    <div class="finding-context">
      <span class="finding-label">Why flagged</span>
      ${esc(f.description)}
    </div>
    ${f.code_snippet ? `<div class="finding-code">${esc(f.code_snippet)}</div>` : ''}
    ${f.remediation ? `
      <div class="finding-remediation">
        <span class="finding-label">How to fix</span>
        ${esc(f.remediation)}
      </div>` : ''}
    <div class="finding-path">
      <span class="finding-label">WDAC/CLM rollout path</span>
      <ul class="finding-path-list">
        <li>Best: refactor to a CLM-safe pattern and re-test.</li>
        <li>If business-required, prefer signed allow rules over one-off bypasses.</li>
        <li>Last resort: allow by hash for this exact file, then re-hash after edits.</li>
      </ul>
    </div>
    ${f.wdac_rule_hint ? `
      <div class="finding-wdac">
        <span class="finding-label">Rule hint</span>
        ${esc(f.wdac_rule_hint)}
      </div>` : ''}
  `;
}

function normalizeSha256(value) {
  const normalized = String(value || '').trim().toUpperCase();
  return /^[A-F0-9]{64}$/.test(normalized) ? normalized : '';
}

function copyText(text, el) {
  navigator.clipboard.writeText(text).then(() => {
    el.classList.add('copied');
    setTimeout(() => el.classList.remove('copied'), 2000);
  });
}

document.addEventListener('click', (e) => {
  const copyEl = e.target.closest('.js-copy-hash');
  if (!copyEl) return;
  const hash = normalizeSha256(copyEl.getAttribute('data-copy-text'));
  if (!hash) return;
  copyText(hash, copyEl);
});

// Keyboard shortcut
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    if (!analyzeBtn.disabled) analyzeBtn.click();
  }
});

// Single-file export
document.getElementById('export-json').addEventListener('click', () => {
  if (!lastAnalysisResult) return;
  const blob = new Blob([JSON.stringify(lastAnalysisResult, null, 2)], {type: 'application/json'});
  downloadBlob(blob, currentFilename.replace(/\.\w+$/, '') + '_clm-forge-report.json');
});

document.getElementById('export-html').addEventListener('click', async () => {
  const content = editor.value.trim();
  if (!content) return;
  const btn = document.getElementById('export-html');
  btn.textContent = '...';
  btn.disabled = true;
  try {
    const resp = await fetch('/api/report/html', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({content, filename: currentFilename}),
    });
    if (!resp.ok) throw new Error('Report generation failed');
    const html = await resp.text();
    downloadBlob(new Blob([html], {type: 'text/html'}), currentFilename.replace(/\.\w+$/, '') + '_clm-forge-report.html');
  } catch (err) { alert('Failed to generate HTML report: ' + err.message); }
  finally { btn.textContent = 'HTML'; btn.disabled = false; }
});

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ============================================================================
// BATCH MODE
// ============================================================================

const focusBackBar = document.getElementById('focus-back-bar');
const focusCurrentName = document.getElementById('focus-current-name');
const focusCurrentPos = document.getElementById('focus-current-pos');
const focusPrevBtn = document.getElementById('focus-prev');
const focusNextBtn = document.getElementById('focus-next');

function enterSingleMode() {
  singleMode.hidden = false;
  batchMode.hidden = true;
  focusBackBar.hidden = true;
  focusedBatchIdx = -1;
  analyzeBtn.disabled = !editor.value.trim();
}

function enterBatchMode() {
  singleMode.hidden = true;
  batchMode.hidden = false;
  focusBackBar.hidden = true;
  focusedBatchIdx = -1;
  analyzeBtn.disabled = batchScripts.length === 0;
  renderBatchFileStrip();
  if (!lastBatchResult) {
    batchSummary.innerHTML = `
      <div class="batch-empty">
        <div class="batch-empty-icon">&#128221;</div>
        <p><strong>${batchScripts.length} script${batchScripts.length !== 1 ? 's' : ''} queued</strong></p>
        <p class="meta">Click <strong>Analyze</strong> to run the audit across all scripts.</p>
      </div>`;
    batchFindingsList.innerHTML = '';
    batchExportBar.style.display = 'none';
  }
}

// Load one batch script into the full-size split view (editor left, findings right).
// This is the "focus" experience the user wanted — the cramped accordion is only a preview.
function focusScriptFromBatch(idx) {
  if (!lastBatchResult || !lastBatchResult.scripts[idx]) return;
  const script = lastBatchResult.scripts[idx];
  const sourceInput = batchScripts.find(b => b.filename === script.filename);

  focusedBatchIdx = idx;
  currentFilename = script.filename;
  currentFindings = script.findings || [];
  lastAnalysisResult = {...script, _source: sourceInput ? sourceInput.content : ''};

  // Show the single-mode layout, but with batch back-nav on top
  singleMode.hidden = false;
  batchMode.hidden = true;
  focusBackBar.hidden = false;

  // Populate editor with the script's source
  editor.value = sourceInput ? sourceInput.content : '';
  filenameDisplay.textContent = script.filename;
  updateLineNumbers();

  // Render findings using the already-analyzed results
  findingsList.innerHTML = '';
  renderSummary(script.summary, script.analysis_method);
  renderFilters();
  renderFindings();
  renderWDACHash(script.wdac_hash);
  renderCLMDynamic(script.clm_dynamic_results, script.analysis_method);
  document.getElementById('export-bar').style.display = 'flex';

  // Update the back-bar state
  focusCurrentName.textContent = script.filename;
  focusCurrentPos.textContent = `${idx + 1} of ${lastBatchResult.scripts.length}`;
  focusPrevBtn.disabled = idx <= 0;
  focusNextBtn.disabled = idx >= lastBatchResult.scripts.length - 1;
}

document.getElementById('focus-back-btn').addEventListener('click', () => {
  if (!lastBatchResult) { enterSingleMode(); return; }
  enterBatchMode();
  renderBatchResults();  // restore portfolio view
});

focusPrevBtn.addEventListener('click', () => {
  if (focusedBatchIdx > 0) focusScriptFromBatch(focusedBatchIdx - 1);
});
focusNextBtn.addEventListener('click', () => {
  if (lastBatchResult && focusedBatchIdx < lastBatchResult.scripts.length - 1) {
    focusScriptFromBatch(focusedBatchIdx + 1);
  }
});

function renderBatchFileStrip() {
  batchFileStrip.innerHTML = batchScripts.map((s, i) => `
    <span class="file-pill" title="${esc(s.filename)}">
      <span class="file-pill-name">${esc(s.filename)}</span>
      <button class="file-pill-x" onclick="removeBatchScript(${i})" title="Remove">&times;</button>
    </span>`).join('');
}

function removeBatchScript(idx) {
  batchScripts.splice(idx, 1);
  if (batchScripts.length === 0) { enterSingleMode(); return; }
  // clear results if they no longer match
  lastBatchResult = null;
  enterBatchMode();
}

async function runBatchAnalysis() {
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = 'Analyzing...';
  batchSummary.innerHTML = `<div class="batch-empty"><p class="meta">Analyzing ${batchScripts.length} script${batchScripts.length !== 1 ? 's' : ''}…</p></div>`;
  batchFindingsList.innerHTML = '';
  try {
    const resp = await fetch('/api/analyze-batch', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({scripts: batchScripts, fail_on: failOn || null}),
    });
    if (!resp.ok) throw new Error((await resp.json()).detail || 'Batch analysis failed');
    lastBatchResult = await resp.json();
    renderBatchResults();
  } catch (err) {
    batchSummary.innerHTML = `<div class="batch-empty"><p style="color:var(--ms-red)">Error: ${esc(err.message)}</p></div>`;
  } finally {
    analyzeBtn.disabled = batchScripts.length === 0;
    analyzeBtn.textContent = 'Analyze';
  }
}

function renderBatchResults() {
  const {scripts, aggregate} = lastBatchResult;
  const ci = aggregate.ci_pass !== undefined ? aggregate.ci_pass : true;
  const ciBadge = aggregate.fail_on
    ? `<span class="ci-badge ${ci ? 'ci-pass' : 'ci-fail'}">${ci ? '&#10003; CI PASS' : '&#10007; CI FAIL'} (fail-on: ${esc(aggregate.fail_on)})</span>`
    : '';

  batchSummary.innerHTML = `
    <div class="batch-summary-row">
      <div class="batch-stat">
        <div class="batch-stat-num">${aggregate.total_scripts}</div>
        <div class="batch-stat-label">Scripts</div>
      </div>
      <div class="batch-stat">
        <div class="batch-stat-num">${aggregate.total_findings}</div>
        <div class="batch-stat-label">Findings</div>
      </div>
      <div class="batch-stat">
        <div class="batch-stat-num c-critical">${aggregate.severity_counts.Critical || 0}</div>
        <div class="batch-stat-label">Critical</div>
      </div>
      <div class="batch-stat">
        <div class="batch-stat-num c-high">${aggregate.severity_counts.High || 0}</div>
        <div class="batch-stat-label">High</div>
      </div>
      <div class="batch-stat">
        <div class="batch-stat-num c-medium">${aggregate.severity_counts.Medium || 0}</div>
        <div class="batch-stat-label">Medium</div>
      </div>
      <div class="batch-stat">
        <div class="batch-stat-num c-low">${aggregate.severity_counts.Low || 0}</div>
        <div class="batch-stat-label">Low</div>
      </div>
      <div class="batch-stat">
        <div class="batch-stat-num ${aggregate.scripts_clean === aggregate.total_scripts ? 'c-pass' : ''}">${aggregate.scripts_clean}/${aggregate.total_scripts}</div>
        <div class="batch-stat-label">Clean</div>
      </div>
      <div class="batch-stat">
        <div class="batch-stat-num ${aggregate.average_score >= 80 ? 'c-pass' : aggregate.average_score >= 50 ? 'c-high' : 'c-critical'}">${aggregate.average_score}</div>
        <div class="batch-stat-label">Avg Score</div>
      </div>
      ${ciBadge ? `<div class="batch-stat-ci">${ciBadge}</div>` : ''}
    </div>`;

  // Sort scripts: failing first (critical > high > medium > low > clean)
  const sorted = [...scripts].sort((a, b) => {
    const sA = (a.summary?.Critical || 0) * 1000 + (a.summary?.High || 0) * 100 + (a.summary?.Medium || 0) * 10 + (a.summary?.Low || 0);
    const sB = (b.summary?.Critical || 0) * 1000 + (b.summary?.High || 0) * 100 + (b.summary?.Medium || 0) * 10 + (b.summary?.Low || 0);
    return sB - sA;
  });

  batchFindingsList.innerHTML = sorted.map((s, i) => renderScriptCard(s, i)).join('');
  batchExportBar.style.display = 'flex';
}

function renderScriptCard(script, idx) {
  const s = script.summary || {};
  const total = s.total_findings || 0;
  const score = script.score ?? 100;
  const scoreCls = score >= 80 ? 'c-pass' : score >= 50 ? 'c-high' : 'c-critical';
  const clean = total === 0;
  const clm = script.clm_dynamic_results || {};
  const clmBlocked = clm.blockedByCLM || 0;
  const dotRow = [
    s.Critical ? `<span class="dot-count"><span class="summary-dot critical"></span>${s.Critical}</span>` : '',
    s.High ? `<span class="dot-count"><span class="summary-dot high"></span>${s.High}</span>` : '',
    s.Medium ? `<span class="dot-count"><span class="summary-dot medium"></span>${s.Medium}</span>` : '',
    s.Low ? `<span class="dot-count"><span class="summary-dot low"></span>${s.Low}</span>` : '',
    clmBlocked ? `<span class="dot-count clm-blocked-chip" title="Blocked by CLM at runtime">CLM×${clmBlocked}</span>` : '',
  ].filter(Boolean).join('');

  const findings = script.findings || [];
  const findingsHtml = findings.length === 0
    ? `<div class="script-clean">&#10003; No CLM blockers detected for this script.</div>`
    : findings.slice().sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4) || a.line - b.line)
        .map(f => `
          <div class="finding-row severity-${f.severity.toLowerCase()}">
            <div class="finding-row-header">
              <span class="badge ${f.severity.toLowerCase()}">${esc(f.severity)}</span>
              <span class="finding-row-rule">${esc(f.rule_id)}: ${esc(f.rule_name)}</span>
              <span class="line-badge">Line ${f.line}</span>
            </div>
            ${buildFindingDetailsHtml(f)}
          </div>`).join('');

  // Dynamic CLM details
  let clmHtml = '';
  const ranDynamic = (script.analysis_method || '').includes('constrained_runspace');
  if (ranDynamic) {
    if ((clm.errors || []).length === 0) {
      clmHtml = `<div class="clm-dynamic-section clm-dynamic-pass"><div class="clm-dynamic-header clm-pass-header"><span><strong>&#10003; Dynamic CLM Test Passed</strong></span><span class="clm-pass-badge">0 errors</span></div></div>`;
    } else {
      clmHtml = `<div class="clm-dynamic-section"><div class="clm-dynamic-header"><strong>Dynamic CLM Test</strong> <span class="meta">${clmBlocked} blocked, ${(clm.otherErrors||0)} other</span></div></div>`;
    }
  }

  const hash = script.wdac_hash ? normalizeSha256(script.wdac_hash.sha256) : '';
  const wdacHtml = hash ? `
    <div class="wdac-hash-box">
      <div class="wdac-hash-title">WDAC SHA256</div>
      <div class="wdac-hash-value js-copy-hash" data-copy-text="${hash}" title="Click to copy">
        ${hash}<span class="copy-hint">click to copy</span>
      </div>
    </div>` : '';

  // idx passed to renderScriptCard is the sort-order index; use the true lastBatchResult index so focus works
  const realIdx = lastBatchResult ? lastBatchResult.scripts.findIndex(s => s.filename === script.filename) : idx;

  return `
    <details class="script-card ${clean ? 'script-clean-card' : ''}" ${total > 0 && idx === 0 ? 'open' : ''}>
      <summary class="script-card-summary">
        <div class="script-card-title">
          <span class="script-expand-indicator">&#9656;</span>
          <span class="script-name">${esc(script.filename)}</span>
          <span class="script-meta">${script.total_lines || 0} lines</span>
        </div>
        <div class="script-card-stats">
          ${dotRow || '<span class="dot-count c-pass"><span class="summary-dot pass"></span>clean</span>'}
          <span class="score-chip ${scoreCls}">score ${score}</span>
          <button class="script-view-btn" onclick="event.preventDefault();event.stopPropagation();focusScriptFromBatch(${realIdx})" title="Open full view (editor + findings side-by-side)">View &rarr;</button>
        </div>
      </summary>
      <div class="script-card-body">
        <div class="script-method">${formatMethodLabel(script.analysis_method)}</div>
        ${findingsHtml}
        ${clmHtml}
        ${wdacHtml}
      </div>
    </details>`;
}

// Fail-on selector
failOnSelect.addEventListener('change', async (e) => {
  failOn = e.target.value;
  if (lastBatchResult) await runBatchAnalysis();
});

// Batch exports
document.getElementById('batch-export-json').addEventListener('click', () => {
  if (!lastBatchResult) return;
  const blob = new Blob([JSON.stringify(lastBatchResult, null, 2)], {type: 'application/json'});
  downloadBlob(blob, 'clm-forge-batch.json');
});

document.getElementById('batch-export-html').addEventListener('click', async () => {
  if (!lastBatchResult) return;
  const btn = document.getElementById('batch-export-html');
  btn.textContent = '...';
  btn.disabled = true;
  try {
    // Include source in payload for the report
    const scriptsWithSource = lastBatchResult.scripts.map(s => {
      const input = batchScripts.find(b => b.filename === s.filename);
      return {...s, _source: input ? input.content : ''};
    });
    const resp = await fetch('/api/report/html-batch', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({scripts: scriptsWithSource}),
    });
    if (!resp.ok) throw new Error('Report failed');
    const html = await resp.text();
    downloadBlob(new Blob([html], {type: 'text/html'}), 'clm-forge-batch-report.html');
  } catch (err) { alert('HTML export failed: ' + err.message); }
  finally { btn.textContent = 'HTML'; btn.disabled = false; }
});

document.getElementById('batch-export-csv').addEventListener('click', async () => {
  if (!lastBatchResult) return;
  const resp = await fetch('/api/export/csv', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({scripts: lastBatchResult.scripts}),
  });
  if (!resp.ok) { alert('CSV export failed'); return; }
  const text = await resp.text();
  downloadBlob(new Blob([text], {type: 'text/csv'}), 'clm-forge-findings.csv');
});

document.getElementById('batch-export-sarif').addEventListener('click', async () => {
  if (!lastBatchResult) return;
  const resp = await fetch('/api/export/sarif', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({scripts: lastBatchResult.scripts}),
  });
  if (!resp.ok) { alert('SARIF export failed'); return; }
  const sarif = await resp.json();
  downloadBlob(new Blob([JSON.stringify(sarif, null, 2)], {type: 'application/sarif+json'}), 'clm-forge.sarif');
});

// Expose functions used by inline handlers
window.toggleFinding = toggleFinding;
window.scrollToLine = scrollToLine;
window.copyText = copyText;
window.removeBatchScript = removeBatchScript;
window.focusScriptFromBatch = focusScriptFromBatch;
