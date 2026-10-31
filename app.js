import { sha256Hex, createManifest, validateManifest, compareManifests, hashDiff, formatBytes, normalisePath } from "./src/fim.js";
import { DEMO_FILES, ATTACK } from "./src/demo-site.js";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const enc = new TextEncoder();
const clock = () => new Date().toLocaleTimeString("en-GB");

/* ======================= demo ======================= */
let files = { ...DEMO_FILES };
let baseFiles = null, baseManifest = null, baseTime = "";
let curHashes = {};
let result = null, stale = false;
let selected = "config.php";

async function manifestOf(fs) {
  const entries = await Promise.all(Object.entries(fs).map(async ([path, c]) => ({ path, size: enc.encode(c).length, sha256: await sha256Hex(c) })));
  return createManifest(entries, { root: "demo-site" });
}
async function refreshHashes() {
  curHashes = Object.fromEntries(await Promise.all(Object.entries(files).map(async ([p, c]) => [p, await sha256Hex(c)])));
}

const CHIP = {
  modified: ["c-mod", "Modified"], added: ["c-add", "Added"], removed: ["c-del", "Removed"], unchanged: ["c-ok", "OK"],
};
function statusOf(path) {
  if (!result || stale) return null;
  if (result.modified.some((x) => x.path === path)) return "modified";
  if (result.added.some((x) => x.path === path)) return "added";
  if (result.removed.some((x) => x.path === path)) return "removed";
  return "unchanged";
}

function renderTree(flash = []) {
  const removed = result && !stale ? result.removed.map((x) => x.path) : [];
  const paths = [...new Set([...Object.keys(files), ...removed])].sort();
  $("tree").innerHTML = paths.map((p) => {
    const st = statusOf(p);
    const h = files[p] !== undefined ? curHashes[p] : baseManifest?.files[p]?.sha256;
    const chip = st ? `<span class="chip ${CHIP[st][0]}">${CHIP[st][1]}</span>` : baseManifest && !baseManifest.files[p] ? '<span class="chip c-new">New</span>' : "";
    return `<li class="${st === "removed" ? "removed" : ""} ${flash.includes(p) ? "flash" : ""}"><button type="button" data-p="${esc(p)}" aria-current="${p === selected}">
      <span class="p">${esc(p)}</span>${chip}<span class="h">sha256 ${h ? esc(h.slice(0, 16)) + "…" : "…"}</span></button></li>`;
  }).join("");
}
$("tree").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) { selected = b.dataset.p; renderTree(); renderEditor(); } });

function renderEditor() {
  const exists = files[selected] !== undefined;
  $("edLabel").textContent = exists ? `Edit ${selected}` : `${selected} (deleted)`;
  $("ed").value = exists ? files[selected] : "";
  $("ed").disabled = !exists;
  renderHashbox();
}
function renderHashbox() {
  const cur = curHashes[selected], base = baseManifest?.files[selected]?.sha256;
  let html = "";
  if (base) html += `<span class="k">Baseline</span><span>${base}</span>`;
  if (cur) {
    const diff = base ? new Set(hashDiff(base, cur)) : new Set();
    const shown = cur.split("").map((ch, i) => (diff.has(i) ? `<span class="d">${ch}</span>` : ch)).join("");
    html += `<span class="k">Now</span><span>${shown}</span>`;
    if (base) html += `<span class="note">${diff.size ? `<strong>${diff.size} of 64</strong> characters differ from the baseline.` : "Matches the baseline exactly."}</span>`;
    else if (baseManifest) html += `<span class="note">This file didn't exist when the baseline was taken.</span>`;
  } else if (base) html += `<span class="note">This file has been deleted since the baseline.</span>`;
  $("hashbox").innerHTML = html || '<span class="note">Take a baseline to compare hashes.</span>';
}
let edTimer;
$("ed").addEventListener("input", () => {
  files[selected] = $("ed").value;
  clearTimeout(edTimer);
  edTimer = setTimeout(async () => { curHashes[selected] = await sha256Hex(files[selected]); markStale("You edited " + selected + "."); renderTree(); renderHashbox(); }, 120);
});

function setStatus(html) { $("status").innerHTML = html; }
function markStale(why) {
  if (!baseManifest) return;
  stale = true;
  setStatus(`${esc(why)} Files have changed since the last scan. Press <b>Scan now</b>.`);
  $("bScan").classList.add("nudge");
}

async function takeBaseline() {
  baseFiles = { ...files };
  baseManifest = await manifestOf(files);
  baseTime = clock();
  result = null; stale = false;
  setCounts({ modified: [], added: [], removed: [], unchanged: Object.keys(files).map((path) => ({ path })) });
  $("verdict").className = "verdict";
  $("verdict").innerHTML = "<strong>Baseline taken</strong><span>Every file is fingerprinted. Now simulate an attack or edit a file, then scan.</span>";
  setStatus(`Baseline taken at <b>${baseTime}</b> · ${Object.keys(files).length} files fingerprinted.`);
  $("bScan").classList.remove("nudge");
  addAlert({ kind: "info", text: `Baseline taken: ${Object.keys(files).length} files fingerprinted with SHA-256.` });
  renderTree(); renderHashbox();
}

async function simulateAttack() {
  if (!baseManifest) await takeBaseline();
  files = ATTACK.apply(files);
  await refreshHashes();
  selected = "config.php";
  markStale("Simulated attack: someone got in and changed the site.");
  renderTree(["config.php", ".htaccess", "uploads/avatar.php"]);
  renderEditor();
}

function explain(change, kind) {
  const p = change.path, content = files[p] ?? "";
  if (kind === "added" && change.severity === "critical") return "New script in an upload folder. This is the classic sign of a web shell, which gives an attacker remote control of the server.";
  if (kind === "modified" && /eval\s*\(\s*base64_decode/i.test(content)) return "Contents changed and now contain eval(base64_decode(…)), a common way to hide a backdoor.";
  if (kind === "modified" && p.endsWith(".htaccess") && /\+Indexes/.test(content)) return "Access rules changed: directory listing is now switched on and the config file is no longer protected.";
  if (kind === "modified" && change.severity === "high") return "A configuration file changed. Check it for injected code or weakened settings.";
  if (kind === "added") return "A file appeared that wasn't in the baseline.";
  if (kind === "removed") return "This file was deleted since the baseline.";
  return "Contents changed since the baseline.";
}
const SEV = { critical: "c-crit", high: "c-high", medium: "c-medium", low: "c-low" };
function addAlert({ kind, path, severity, text }) {
  const list = $("alerts");
  list.querySelector(".empty")?.remove();
  const li = document.createElement("li");
  li.className = "in";
  const label = { modified: "Modified", added: "Added", removed: "Removed", info: "Info", ok: "All clear" }[kind];
  li.innerHTML = `<div class="top"><time>${clock()}</time>${severity ? `<span class="chip ${SEV[severity]}">${severity}</span>` : `<span class="chip ${kind === "ok" ? "c-ok" : "c-new"}">${label}</span>`}
    ${path ? `<span class="path">${esc(label)}: ${esc(path)}</span>` : ""}</div><p>${esc(text)}</p>`;
  list.prepend(li);
}
function setCounts(r) {
  $("nMod").textContent = r.modified.length; $("nAdd").textContent = r.added.length;
  $("nDel").textContent = r.removed.length; $("nOk").textContent = r.unchanged.length;
}

async function scan() {
  if (!baseManifest) { await takeBaseline(); return; }
  const cur = await manifestOf(files);
  result = compareManifests(baseManifest, cur); stale = false;
  $("bScan").classList.remove("nudge");
  setCounts(result);
  const changes = [
    ...result.added.map((c) => ["added", c]), ...result.modified.map((c) => ["modified", c]), ...result.removed.map((c) => ["removed", c]),
  ].sort((a, b) => ["critical", "high", "medium", "low"].indexOf(b[1].severity) - ["critical", "high", "medium", "low"].indexOf(a[1].severity));
  if (result.clean) {
    $("verdict").className = "verdict clean";
    $("verdict").innerHTML = `<strong>✓ All ${result.unchanged.length} files match the baseline</strong><span>No files were changed, added or removed.</span>`;
    addAlert({ kind: "ok", text: `Scan complete: all ${result.unchanged.length} files match the baseline.` });
  } else {
    const n = changes.length, worst = changes.at(-1)?.[1].severity;
    $("verdict").className = "verdict alert";
    $("verdict").innerHTML = `<strong>⚠ ${n} change${n === 1 ? "" : "s"} detected</strong><span>Highest severity: ${worst}. Investigate before trusting this server.</span>`;
    changes.forEach(([kind, c]) => addAlert({ kind, path: c.path, severity: c.severity, text: explain(c, kind) }));
  }
  setStatus(`Scanned at <b>${clock()}</b> against the baseline from <b>${baseTime}</b>.`);
  renderTree(); renderHashbox();
}

async function reset() {
  files = { ...DEMO_FILES }; selected = "config.php";
  $("alerts").innerHTML = '<li class="empty">Alerts will appear here, newest first, with a timestamp and severity.</li>';
  await refreshHashes(); await takeBaseline(); renderEditor();
}

$("bBase").addEventListener("click", takeBaseline);
$("bAttack").addEventListener("click", simulateAttack);
$("bScan").addEventListener("click", scan);
$("bReset").addEventListener("click", reset);

/* ======================= own files ======================= */
const MAX_FILE = 200 * 1024 * 1024;
let ownBaseline = null, ownCreated = null;

async function entriesFromFileList(list, { fromFolder }) {
  return [...list].map((f) => ({ file: f, path: normalisePath(f.webkitRelativePath || f.name, { stripRoot: fromFolder && !!f.webkitRelativePath }) }));
}
// Recursively read dropped folders (DataTransferItem.webkitGetAsEntry)
async function entriesFromDrop(dt) {
  const items = [...dt.items].map((i) => i.webkitGetAsEntry?.()).filter(Boolean);
  if (!items.length) return entriesFromFileList(dt.files, { fromFolder: false });
  const out = [];
  const single = items.length === 1 && items[0].isDirectory;
  const walk = async (entry, prefix) => {
    if (entry.isFile) {
      const file = await new Promise((res, rej) => entry.file(res, rej));
      out.push({ file, path: normalisePath(prefix + entry.name) });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      let batch;
      do { batch = await new Promise((res, rej) => reader.readEntries(res, rej)); for (const e of batch) await walk(e, `${prefix}${entry.name}/`); } while (batch.length);
    }
  };
  for (const it of items) {
    if (single) {
      const reader = it.createReader(); let batch;
      do { batch = await new Promise((res, rej) => reader.readEntries(res, rej)); for (const e of batch) await walk(e, ""); } while (batch.length);
    } else await walk(it, "");
  }
  return out;
}
async function hashEntries(entries, outEl) {
  const skip = new Set([".git", "node_modules", "__pycache__", ".DS_Store"]);
  const list = entries.filter((e) => !e.path.split("/").some((s) => skip.has(s)));
  const res = []; let skipped = 0, total = 0;
  for (let i = 0; i < list.length; i++) {
    const { file, path } = list[i];
    if (file.size > MAX_FILE) { skipped++; continue; }
    outEl.textContent = `Hashing ${i + 1} of ${list.length}: ${path}`;
    res.push({ path, size: file.size, sha256: await sha256Hex(await file.arrayBuffer()) });
    total += file.size;
  }
  return { entries: res, skipped, total };
}

async function handleA(entries) {
  const out = $("outA"); out.className = "out";
  if (!entries.length) { out.textContent = "No files found. Try choosing a folder instead."; return; }
  const { entries: hashed, skipped, total } = await hashEntries(entries, out);
  ownBaseline = createManifest(hashed, { root: "my-files" });
  out.textContent = `Fingerprinted ${hashed.length} files (${formatBytes(total)}).${skipped ? ` Skipped ${skipped} file(s) over 200 MB.` : ""} Download the baseline and keep it somewhere safe.`;
  $("saveA").hidden = false;
}
$("saveA").addEventListener("click", () => {
  if (!ownBaseline) return;
  const blob = new Blob([JSON.stringify(ownBaseline, null, 2) + "\n"], { type: "application/json" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "baseline.json";
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

$("loadB").addEventListener("change", async (e) => {
  const out = $("outB"); const f = e.target.files[0]; if (!f) return;
  try {
    ownCreated = validateManifest(JSON.parse(await f.text()));
    out.className = "out";
    out.textContent = `Baseline loaded: ${Object.keys(ownCreated.files).length} files, created ${new Date(ownCreated.created).toLocaleString("en-GB")}. Now choose the folder to check.`;
  } catch (err) {
    ownCreated = null; out.className = "out err";
    out.textContent = err instanceof SyntaxError ? "That file isn't valid JSON." : err.message;
  }
});
async function handleB(entries) {
  const out = $("outB");
  if (!ownCreated) { out.className = "out err"; out.textContent = "Load your baseline.json first, then choose the folder."; return; }
  out.className = "out";
  const { entries: hashed } = await hashEntries(entries, out);
  const r = compareManifests(ownCreated, createManifest(hashed));
  const rows = [...r.added.map((c) => ["Added", c]), ...r.modified.map((c) => ["Modified", c]), ...r.removed.map((c) => ["Removed", c])];
  out.textContent = r.clean ? `✓ All ${r.unchanged.length} files match the baseline.` : `⚠ ${rows.length} change(s) found, ${r.unchanged.length} unchanged.`;
  $("resultWrap").hidden = r.clean;
  $("resultB").innerHTML = rows.map(([k, c]) => `<tr><td class="m">${esc(c.path)}</td><td>${k}</td><td><span class="chip ${SEV[c.severity]}">${c.severity}</span></td></tr>`).join("");
}

for (const [id, fn, folder] of [["folderA", handleA, true], ["filesA", handleA, false], ["folderB", handleB, true], ["filesB", handleB, false]]) {
  $(id).addEventListener("change", async (e) => { await fn(await entriesFromFileList(e.target.files, { fromFolder: folder })); e.target.value = ""; });
}
for (const [id, fn] of [["dropA", handleA], ["dropB", handleB]]) {
  const z = $(id);
  z.addEventListener("dragover", (e) => { e.preventDefault(); z.classList.add("over"); });
  z.addEventListener("dragleave", () => z.classList.remove("over"));
  z.addEventListener("drop", async (e) => { e.preventDefault(); z.classList.remove("over"); await fn(await entriesFromDrop(e.dataTransfer)); });
}

/* ======================= start ======================= */
(async () => { await refreshHashes(); await takeBaseline(); renderEditor(); })();
