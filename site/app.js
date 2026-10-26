import init, { verify, inspect } from "./pkg/externalize_wasm.js";

const resultEl = document.getElementById("result");
const SAMPLE = "samples/mainnet-64791359.json";
const HORIZON = "https://horizon.stellar.org";
// The bundle node: ?node=URL, else the page's <meta name="exnode">. It is untrusted.
const NODE = (new URLSearchParams(location.search).get("node") || document.querySelector('meta[name="exnode"]').content || "").replace(/\/+$/, "");
let ready = false;
let download = null; // object URL of the last proof built here

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const when = (unix) => new Date(unix * 1000).toUTCString().replace("GMT", "UTC");
const short = (h) => `${h.slice(0, 12)}…${h.slice(-6)}`;

function message(html) { resultEl.innerHTML = html; }

function run(text, note, file) {
  if (!ready) return;
  message(`<p class="muted">Verifying…</p>`);
  // Let the message paint before the (fast) synchronous check.
  requestAnimationFrame(() => setTimeout(() => render(text, note, file), 0));
}

function render(text, note, file) {
  const t0 = performance.now();
  const r = verify(text, undefined, true);
  const elapsedMs = Math.round(performance.now() - t0);
  if (!r || !r.verified) return renderRejected(text, r ? r.error : "unknown error", note);
  const l = r.ledger;
  const agreed = l.orgs.filter((o) => o.satisfied).length;
  const signatures = l.signers.length;
  const hashChains = 1 + (r.claims ? r.claims.length : 0);
  const bytes = new Blob([text]).size;
  const kb = Math.round(bytes / 1024);

  let html = `<p class="verdict"><span class="mark" aria-hidden="true">✓</span>Verified</p>`;
  html += `<p class="muted">Checked ${signatures.toLocaleString()} Ed25519 signature${signatures === 1 ? "" : "s"} and ${hashChains.toLocaleString()} hash chain${hashChains === 1 ? "" : "s"} in ${elapsedMs.toLocaleString()} ms, here in your browser. Bundle: ${kb.toLocaleString()} KB.</p>`;
  if (note) html += `<p class="muted">${note}</p>`;
  html += `<dl class="facts">
    <dt>Ledger</dt><dd>${l.sequence.toLocaleString("en-US")}</dd>
    <dt>Closed</dt><dd>${esc(when(l.close_time))}</dd>
    <dt>Ledger hash</dt><dd class="mono">${esc(l.hash)}</dd>
    <dt>Signed by</dt><dd>${l.signers.length} trusted validators; ${agreed} of ${l.orgs.length} organizations agree</dd>
  </dl>`;
  if (l.orgs.length) {
    html += `<h3>Who certified this ledger</h3><div class="orgs">`;
    html += l.orgs.map((o) => `<div class="org ${o.satisfied ? "ok" : ""}"><b>${esc(o.name)}</b>${o.signed} of ${o.validators} validators signed</div>`).join("");
    html += `</div>`;
  }
  html += `<h3>What is proven</h3>`;
  if (!r.claims.length) html += `<p class="muted">This bundle proves only the ledger itself.</p>`;
  for (const c of r.claims) {
    const status = c.succeeded ? `<span class="tag">succeeded</span>` : `<span class="tag fail">applied, failed</span>`;
    if (c.kind === "transaction") {
      html += `<div class="claim">Transaction <span class="mono">${esc(short(c.tx_hash))}</span> was applied in this ledger ${status}</div>`;
    } else {
      const events = (c.decoded_events || []).map((e) => JSON.stringify(e, null, 2)).join("\n\n");
      html += `<details class="claim"><summary>Contract call in <span class="mono">${esc(short(c.tx_hash))}</span>, operation ${c.op_index}: return value and ${c.events} event${c.events === 1 ? "" : "s"} proven ${status}</summary>
        ${events ? `<pre>${esc(events)}</pre>` : `<p class="muted">No events.</p>`}</details>`;
    }
  }
  if (file) {
    if (download) URL.revokeObjectURL(download);
    download = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    html += `<p class="muted"><a href="${download}" download="${esc(file)}">Download this proof</a> to check it again later, offline,
      with <code>externalize verify ${esc(file)}</code>.</p>`;
  }
  message(html);
}

function renderRejected(text, error, note) {
  let html = `<p class="verdict bad"><span class="mark" aria-hidden="true">✕</span>Rejected</p>`;
  if (note) html += `<p class="muted">${note}</p>`;
  html += `<div class="reason"><strong>Why:</strong> ${esc(error)}</div>`;
  try {
    const seen = inspect(text);
    html += `<h3>What the bundle claimed (unverified)</h3><dl class="facts">
      <dt>Network</dt><dd>${esc(seen.network)}</dd>
      <dt>Ledger</dt><dd>${seen.ledger.sequence.toLocaleString("en-US")}</dd>
      <dt>Claims</dt><dd>${seen.claims.length}</dd></dl>
      <p class="muted">Nothing in a rejected bundle can be relied on. A genuine bundle from <code>exnode</code> verifies; if yours should, check it was built for the same network.</p>`;
  } catch {
    html += `<p class="muted">This doesn't look like an Externalize bundle at all. Bundles are JSON files produced by <a href="https://github.com/Externalize-Labs/externalize-node">exnode</a>.</p>`;
  }
  message(html);
}

async function sample() {
  const res = await fetch(SAMPLE);
  if (!res.ok) throw new Error(`the sample bundle could not be downloaded (HTTP ${res.status})`);
  return res.text();
}

// Change one character inside a proven contract event: the data the contract emitted.
function tamper(text) {
  const b = JSON.parse(text);
  const claim = b.claims.find((c) => c.kind === "invocation" && c.events && c.events.length);
  const ev = claim.events[0];
  const i = Math.floor(ev.length / 2);
  claim.events[0] = ev.slice(0, i) + (ev[i] === "A" ? "B" : "A") + ev.slice(i + 1);
  return JSON.stringify(b);
}

function fail(what, e) {
  message(`<div class="reason"><strong>${esc(what)}.</strong> ${esc(e.message || e)}. Check your connection and try again.</div>`);
}

// --- Proving a transaction by hash -------------------------------------------

const form = document.getElementById("prove");
const hashInput = document.getElementById("hash");
const hashError = document.getElementById("hash-error");
const proveBtn = document.getElementById("prove-btn");
const CHECKPOINT = 64;
let retry = null; // pending automatic retry while a ledger awaits archiving

// A problem the user can act on: what happened, and what to do next.
class Problem extends Error {
  constructor(what, next) { super(what); this.next = next; }
}

// A bare hash, or any link that contains one (stellar.expert, Horizon, lab).
function parseHash(input) {
  const m = String(input).trim().toLowerCase().match(/(?:^|[^0-9a-f])([0-9a-f]{64})(?![0-9a-f])/);
  return m ? m[1] : null;
}

function showFieldError(text) {
  hashError.textContent = text;
  hashError.hidden = !text;
  hashInput.setAttribute("aria-invalid", text ? "true" : "false");
}

function validateField() {
  const v = hashInput.value.trim();
  if (!v) return showFieldError("Paste a transaction hash first."), null;
  const h = parseHash(v);
  showFieldError(h ? "" : "That isn't a transaction hash. It should be 64 characters of 0–9 and a–f; a stellar.expert link that ends in one works too.");
  return h;
}

function steps(current, note = "") {
  const all = ["Find the transaction's ledger", "Build the proof", "Check the validators' signatures"];
  message(`<ol class="steps">${all.map((s, i) => `<li class="${i < current ? "done" : i === current ? "now" : ""}">${s}</li>`).join("")}</ol>
    ${note ? `<p class="muted">${note}</p>` : ""}`);
}

async function getJSON(url, what) {
  let res;
  try { res = await fetch(url); }
  catch { throw new Problem(`${what} couldn't be reached.`, "Check your connection and try again."); }
  let body = null;
  try { body = await res.json(); } catch { /* not JSON */ }
  return { res, body };
}

// Horizon only tells us where to look. Nothing it says is trusted: the
// bundle is checked against validator signatures, whoever built it.
async function lookUp(hash) {
  const { res, body } = await getJSON(`${HORIZON}/transactions/${hash}`, "Horizon");
  if (res.status === 404) throw new Problem("No mainnet transaction has that hash.", "Check that you copied all 64 characters, and that it is a mainnet transaction, not a testnet one.");
  if (res.status === 429) throw new Problem("Horizon is limiting requests from your connection right now.", "Wait a minute, then try again.");
  if (!res.ok || !body) throw new Problem(`Horizon couldn't look the transaction up (HTTP ${res.status}).`, "Try again in a moment.");
  let soroban = false;
  if (body.successful && body.operation_count === 1) {
    const ops = await getJSON(`${HORIZON}/transactions/${hash}/operations?limit=1`, "Horizon");
    soroban = !!ops.body?._embedded?.records?.some((op) => op.type === "invoke_host_function");
  }
  // Results are keyed by the outer hash of a fee-bump transaction.
  return { hash: body.fee_bump_transaction?.hash || body.hash, ledger: body.ledger, soroban };
}

async function nodeProblem(res, body) {
  const detail = body?.error ? ` The node said: "${body.error}".` : "";
  if (res.status === 429) return new Problem("The proof node is busy.", "Wait a few seconds and try again.");
  if (res.status >= 500) return new Problem(`The proof node couldn't build the proof (HTTP ${res.status}).${detail}`, "The history archive or RPC may be slow; try again in a minute.");
  return new Problem(`The proof node refused the request (HTTP ${res.status}).${detail}`, "Try again, or build the bundle yourself with exnode.");
}

async function archiveTip() {
  const { res, body } = await getJSON(`${NODE}/v1/status`, "The proof node");
  if (!res.ok || typeof body?.archive_tip !== "number") throw await nodeProblem(res, body);
  return body.archive_tip;
}

// A Soroban call within RPC's retention is proven with its return value and
// events; anything else, or anything older, as an applied transaction.
async function fetchBundle(tx) {
  if (tx.soroban) {
    const { res, body } = await getJSON(`${NODE}/v1/transactions/${tx.hash}/bundle?op=0`, "The proof node");
    if (res.ok && body) return { text: JSON.stringify(body, null, 2), kind: "invocation" };
    if (![400, 404, 501].includes(res.status)) throw await nodeProblem(res, body);
  }
  const { res, body } = await getJSON(`${NODE}/v1/ledgers/${tx.ledger}/bundle?tx=${tx.hash}`, "The proof node");
  if (!res.ok || !body) throw await nodeProblem(res, body);
  return { text: JSON.stringify(body, null, 2), kind: "transaction" };
}

function waitForArchive(tx, tip, attempt) {
  const checkpoint = Math.ceil((tx.ledger + 1) / CHECKPOINT) * CHECKPOINT - 1;
  const ledgersLeft = Math.max(checkpoint - tip, 0);
  const minutes = Math.max(1, Math.round((ledgersLeft * 6) / 60) + 1);
  message(`<p class="verdict wait"><span class="mark" aria-hidden="true">…</span>Waiting for the history archive</p>
    <p>This transaction is in ledger ${tx.ledger.toLocaleString("en-US")}, but validators have archived only up to
      ${tip.toLocaleString("en-US")}. Its signatures are published with checkpoint ${checkpoint.toLocaleString("en-US")},
      about ${minutes} minute${minutes === 1 ? "" : "s"} from now.</p>
    <p class="muted">This page will try again by itself every 30 seconds (attempt ${attempt}).
      <button type="button" id="cancel-wait">Stop waiting</button></p>`);
  document.getElementById("cancel-wait").addEventListener("click", stopWaiting);
  retry = setTimeout(() => prove(tx.input, attempt + 1), 30_000);
}

function stopWaiting() {
  clearTimeout(retry);
  retry = null;
  proveBtn.disabled = false;
  message(`<p class="muted">Stopped. Choose <strong>Prove it</strong> again whenever you like.</p>`);
}

async function prove(hash, attempt = 1) {
  clearTimeout(retry);
  retry = null;
  if (!NODE) {
    message(`<div class="reason"><strong>No proof node is configured for this page.</strong> Add <code>?node=https://your-exnode</code> to the address, or build a bundle with exnode and open it below.</div>`);
    return;
  }
  proveBtn.disabled = true;
  try {
    steps(0);
    const tx = { ...(await lookUp(hash)), input: hash };
    const tip = await archiveTip();
    if (tx.ledger > tip) return waitForArchive(tx, tip, attempt);
    steps(1, `Ledger ${tx.ledger.toLocaleString("en-US")}. Asking ${esc(new URL(NODE).host)} for the archived signatures and results…`);
    const bundle = await fetchBundle(tx);
    steps(2);
    history.replaceState(null, "", `#tx=${hash}`);
    const what = bundle.kind === "invocation" ? "this Soroban contract call, with its return value and events," : "this transaction";
    run(bundle.text, `The proof of ${what} was built just now by ${esc(new URL(NODE).host)}, which this page does not trust, and checked here.`, `proof-${hash.slice(0, 12)}.json`);
  } catch (e) {
    message(`<div class="reason"><strong>${esc(e.message)}</strong> ${esc(e.next || "Try again in a moment.")}</div>`);
  } finally {
    if (!retry) proveBtn.disabled = false;
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const hash = validateField();
  if (hash && ready) prove(hash);
});
hashInput.addEventListener("blur", () => { if (hashInput.value.trim()) validateField(); });
hashInput.addEventListener("input", () => { if (!hashError.hidden && parseHash(hashInput.value)) showFieldError(""); });

const forgetShared = () => { if (location.hash) history.replaceState(null, "", location.pathname + location.search); };
document.getElementById("sample").addEventListener("click", async () => {
  forgetShared();
  try { run(await sample(), "A real public-network bundle from ledger 64,791,359: one transaction and one Soroban contract call."); }
  catch (e) { fail("Couldn't load the sample", e); }
});
document.getElementById("tamper").addEventListener("click", async () => {
  forgetShared();
  try { run(tamper(await sample()), "The same bundle with one character of a proven contract event changed, as a lying RPC might."); }
  catch (e) { fail("Couldn't load the sample", e); }
});
const read = (file) => file && file.text().then((t) => run(t, `From ${esc(file.name)}.`)).catch((e) => fail("Couldn't read that file", e));
document.getElementById("file").addEventListener("change", (e) => read(e.target.files[0]));
document.addEventListener("dragover", (e) => { e.preventDefault(); document.body.classList.add("dragging"); });
document.addEventListener("dragleave", (e) => { if (!e.relatedTarget) document.body.classList.remove("dragging"); });
document.addEventListener("drop", (e) => { e.preventDefault(); document.body.classList.remove("dragging"); read(e.dataTransfer.files[0]); });

try {
  await init();
  ready = true;
  // Shared links (#tx=<hash>) prove that transaction straight away, on load or
  // when only the fragment changes.
  const fromFragment = () => {
    const shared = parseHash(new URLSearchParams(location.hash.slice(1)).get("tx") || "");
    if (shared) {
      hashInput.value = shared;
      prove(shared);
    }
    return shared;
  };
  window.addEventListener("hashchange", fromFragment);
  if (!fromFragment()) {
    message(`<p class="muted">Paste a mainnet transaction hash above to prove it, or choose <strong>Verify a stored mainnet proof</strong>.</p>`);
  }
} catch {
  message(`<div class="reason">The verifier couldn't load, so nothing can be checked. Your browser may block WebAssembly; try reloading, or a current Chrome, Firefox or Safari.</div>`);
}
