// File integrity monitoring core: hashing, manifests and comparison.
// Pure functions with no DOM access. The manifest format is shared with the
// Python CLI (python/fim.py), so a baseline made by one can be checked by the other.

export const MANIFEST_TOOL = "file-integrity";
export const MANIFEST_VERSION = 1;

const enc = new TextEncoder();

/** SHA-256 of a string, ArrayBuffer or Uint8Array, as lowercase hex. */
export async function sha256Hex(data) {
  const bytes = typeof data === "string" ? enc.encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Normalise a path to forward slashes with no leading "./" or "/". Optionally drop the top folder. */
export function normalisePath(p, { stripRoot = false } = {}) {
  let out = String(p).replace(/\\/g, "/").replace(/^\.\//, "").replace(/^\/+/, "");
  if (stripRoot && out.includes("/")) out = out.slice(out.indexOf("/") + 1);
  return out;
}

/** Build a manifest from [{ path, size, sha256 }]. Paths are sorted so manifests diff cleanly. */
export function createManifest(entries, { root = "", created = new Date().toISOString() } = {}) {
  const files = {};
  [...entries].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)).forEach((e) => {
    files[normalisePath(e.path)] = { sha256: e.sha256.toLowerCase(), size: e.size };
  });
  return { tool: MANIFEST_TOOL, version: MANIFEST_VERSION, algorithm: "sha256", created, root, files };
}

/** Check a parsed manifest has the expected shape. Throws a readable error if not. */
export function validateManifest(m) {
  if (!m || typeof m !== "object") throw new Error("This isn't a baseline file: it doesn't contain a JSON object.");
  if (m.tool !== MANIFEST_TOOL) throw new Error("This JSON wasn't created by File Integrity Monitor.");
  if (m.version !== MANIFEST_VERSION) throw new Error(`Unsupported baseline version ${m.version}. Expected ${MANIFEST_VERSION}.`);
  if (m.algorithm !== "sha256") throw new Error(`Unsupported hash algorithm "${m.algorithm}".`);
  if (!m.files || typeof m.files !== "object") throw new Error("The baseline has no file list.");
  for (const [path, f] of Object.entries(m.files)) {
    if (!f || !/^[0-9a-f]{64}$/.test(f.sha256 ?? "")) throw new Error(`"${path}" has an invalid SHA-256 hash.`);
  }
  return m;
}

/**
 * Rate how worrying a change is. New executable or script files in upload folders and
 * changes to configuration or access files are the classic signs of a compromise.
 */
export function severity(path, kind) {
  const p = path.toLowerCase();
  const name = p.split("/").pop();
  const script = /\.(php\d?|phtml|jsp|aspx?|cgi|pl|py|sh|exe|dll|ps1|bat)$/.test(name);
  const config = /(^|\/)(\.htaccess|\.env|web\.config|wp-config\.php|config\.(php|js|json|ya?ml|ini)|settings\.(py|php)|nginx\.conf|httpd\.conf|crontab|authorized_keys|passwd|shadow)$/.test(p);
  if (kind === "added" && script && /(^|\/)(uploads?|images?|media|tmp|cache|static)\//.test(p)) return "critical";
  if (config && kind !== "unchanged") return "high";
  if (script && kind === "added") return "high";
  if (kind === "removed" && /(^|\/)(robots\.txt|security\.txt|\.htaccess)$/.test(p)) return "medium";
  if (kind === "unchanged") return "none";
  return script ? "medium" : "low";
}

/**
 * Compare a baseline manifest with a current one.
 * Returns { unchanged, modified, added, removed, clean } where each change carries a severity.
 */
export function compareManifests(base, cur) {
  const b = base.files, c = cur.files;
  const unchanged = [], modified = [], added = [], removed = [];
  for (const path of Object.keys(b).sort()) {
    if (!(path in c)) removed.push({ path, before: b[path], severity: severity(path, "removed") });
    else if (b[path].sha256 !== c[path].sha256) modified.push({ path, before: b[path], after: c[path], severity: severity(path, "modified") });
    else unchanged.push({ path });
  }
  for (const path of Object.keys(c).sort()) {
    if (!(path in b)) added.push({ path, after: c[path], severity: severity(path, "added") });
  }
  return { unchanged, modified, added, removed, clean: !modified.length && !added.length && !removed.length };
}

/** Indexes of the hex characters that differ between two hashes (the avalanche effect). */
export function hashDiff(a, b) {
  const out = [];
  for (let i = 0; i < Math.max(a.length, b.length); i++) if (a[i] !== b[i]) out.push(i);
  return out;
}

export function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
