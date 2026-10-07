import init, { verify, inspect } from "./pkg/externalize_wasm.js";

const resultEl = document.getElementById("result");
const SAMPLE = "samples/mainnet-64791359.json";
let ready = false;

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const when = (unix) => new Date(unix * 1000).toUTCString().replace("GMT", "UTC");
const short = (h) => `${h.slice(0, 12)}…${h.slice(-6)}`;

function message(html) { resultEl.innerHTML = html; }

function run(text, note) {
  if (!ready) return;
  message(`<p class="muted">Verifying…</p>`);
  // Let the message paint before the (fast) synchronous check.
  requestAnimationFrame(() => setTimeout(() => render(text, note), 0));
}

function render(text, note) {
  const r = verify(text, undefined, true);
  if (!r || !r.verified) return renderRejected(text, r ? r.error : "unknown error", note);
  const l = r.ledger;
  const agreed = l.orgs.filter((o) => o.satisfied).length;
  let html = `<p class="verdict"><span class="mark" aria-hidden="true">✓</span>Verified</p>`;
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

document.getElementById("sample").addEventListener("click", async () => {
  try { run(await sample(), "A real public-network bundle from ledger 64,791,359: one transaction and one Soroban contract call."); }
  catch (e) { fail("Couldn't load the sample", e); }
});
document.getElementById("tamper").addEventListener("click", async () => {
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
  message(`<p class="muted">Choose <strong>Verify a mainnet proof</strong> to see a real check, or bring your own bundle.</p>`);
} catch {
  message(`<div class="reason">The verifier couldn't load, so nothing can be checked. Your browser may block WebAssembly; try reloading, or a current Chrome, Firefox or Safari.</div>`);
}
