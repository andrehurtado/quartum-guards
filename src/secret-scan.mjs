#!/usr/bin/env node
/**
 * Credential scanner - parameterised, and provable.
 *
 * WHY IT TAKES ITS ROOT AS AN ARGUMENT. The predecessor computed its scan root from its
 * own file location and searched three named sibling directories. Copied into another
 * repository those directories did not exist, the search returned nothing, and it printed
 * "clean across 3 repo(s)" and exited 0 - permanently. Worse, the integrity check meant to
 * catch tampering compared the copy against its own fingerprint, so a faithful-but-useless
 * copy passed. An assay reporting clean because no sample reached the instrument.
 *
 * Two consequences, both structural:
 *   1. the root is an explicit argument, so it cannot be silently wrong
 *   2. `--expect N` asserts a HIT COUNT, so "found nothing" and "scanned nothing" are
 *      distinguishable. A scanner without a positive control is not a control.
 *
 *   node src/secret-scan.mjs <root>                 scan, expect zero hits
 *   node src/secret-scan.mjs <root> --expect 4      positive control
 *   node src/secret-scan.mjs --self-test            scan this repo's own fixture
 */
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { CREDENTIAL_NAME_PATTERNS } from "./project-refs.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const NAME_ALTERNATION = CREDENTIAL_NAME_PATTERNS.join("|");

export const RULES = Object.freeze([
  { id: "sb_secret", re: new RegExp(String.raw`sb_secret_[A-Za-z0-9_-]{8,}`) },
  { id: "named_credential", re: new RegExp(String.raw`(${NAME_ALTERNATION})\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}`) },
  // A service-role JWT is the material the predecessor's own comment claimed to catch and
  // did not: there was no JWT pattern at all.
  //
  // PRECISION MATTERS MORE THAN REACH HERE. Matching any JWT shape flags every Supabase
  // ANON key — which is publishable by design and ships in the browser bundle of all three
  // products. A control that fires on normal, correct code is ignored within a week, and an
  // ignored control is worse than none. So the payload is decoded and only `service_role`
  // is flagged. An undecodable token assigned to a credential-named variable is still
  // caught by the `named_credential` rule above.
  {
    id: "service_role_jwt",
    match: (line) => {
      const m = /eyJ[A-Za-z0-9_-]{6,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{6,}/.exec(line);
      if (!m) return false;
      try {
        const claims = JSON.parse(
          Buffer.from(m[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"),
        );
        return claims?.role === "service_role";
      } catch {
        return false;
      }
    },
  },
  { id: "private_key", re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
]);

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".output", ".wrangler", "coverage"]);
const NUL = String.fromCharCode(0);

/**
 * WHICH FILES. The question is "was a credential COMMITTED", not "is a credential present
 * on this laptop". Scanning the working tree flags every developer's legitimate local
 * .env and teaches people to ignore the scanner. So a git repository is scanned through
 * `git ls-files`; a non-repository falls back to a directory walk (that is how the
 * fabricated fixture in this repo is scanned).
 */
function candidateFiles(root) {
  try {
    const out = execFileSync("git", ["-C", root, "ls-files", "-z"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    const files = out.split(NUL).filter(Boolean);
    if (files.length) return { files, mode: "tracked" };
  } catch { /* not a git repo */ }
  const acc = [];
  (function walk(dir) {
    let entries; try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (SKIP_DIRS.has(e.name)) continue;
      const full = join(dir, e.name);
      if (e.isDirectory()) walk(full); else acc.push(relative(root, full));
    }
  })(root);
  return { files: acc, mode: "walk" };
}

/**
 * NARROW, REASONED EXEMPTIONS. The predecessor excluded EVERY test file, which is far too
 * broad — it silently exempts the largest surface in the repository. Instead a consuming
 * repo may ship `.quartum-secret-scan-allow`, one `path # reason` per line. A reason is
 * mandatory, and unused entries are reported so a stale exemption cannot linger unnoticed.
 *
 * REASON TEXT MUST DESCRIBE MATCHED VALUES, NEVER REPRODUCE THEM.
 *
 * The allowlist file is itself scanned, deliberately: it is the file most likely to
 * accumulate copy-pasted credential material over time, and exempting it would make the
 * exemption register the one blind spot in the repository. The consequence is that a
 * reason quoting the placeholder it describes makes the documentation trip the scanner.
 * That is not a flaw to route around — say "a fabricated opaque-prefixed key", not the key.
 */
export function readAllowlist(root) {
  const p = join(root, ".quartum-secret-scan-allow");
  if (!existsSync(p)) return [];
  return readFileSync(p, "utf8").split("\n")
    .map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))
    .map((l) => {
      const i = l.indexOf("#");
      if (i < 0) throw new Error(`.quartum-secret-scan-allow: "${l}" has no reason. Every exemption must say why.`);
      return { path: l.slice(0, i).trim(), reason: l.slice(i + 1).trim() };
    });
}

export function scan(root) {
  const { files, mode } = candidateFiles(root);
  const allow = readAllowlist(root);
  const allowPaths = new Set(allow.map((a) => a.path));
  const usedAllow = new Set();
  const hits = [];
  let filesScanned = 0;
  for (const rel of files) {
    const full = join(root, rel);
    let st; try { st = statSync(full); } catch { continue; }
    if (!st.isFile() || st.size > 2 * 1024 * 1024) continue;
    let text; try { text = readFileSync(full, "utf8"); } catch { continue; }
    if (text.includes(NUL)) continue;
    filesScanned++;
    for (const line of text.split("\n")) {
      for (const rule of RULES) {
        const fired = rule.match ? rule.match(line) : rule.re.test(line);
        if (!fired) continue;
        if (allowPaths.has(rel)) { usedAllow.add(rel); continue; }
        hits.push({ file: rel, rule: rule.id });
      }
    }
  }
  const staleAllow = allow.filter((a) => !usedAllow.has(a.path)).map((a) => a.path);
  return { hits, filesScanned, mode, staleAllow };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const args = process.argv.slice(2);
  const selfTest = args.includes("--self-test");
  const root = selfTest ? join(HERE, "..", "__fixtures__") : args[0];
  const expectIdx = args.indexOf("--expect");
  const expect = selfTest ? 4 : expectIdx >= 0 ? Number(args[expectIdx + 1]) : 0;

  if (!root) { console.error("usage: secret-scan.mjs <root> [--expect N] | --self-test"); process.exit(2); }
  const { hits, filesScanned, mode, staleAllow } = scan(root);

  if (filesScanned === 0) {
    console.error(`REFUSING - scanned 0 files under ${root}. "no hits" must never mean "no sample".`);
    process.exit(1);
  }
  if (hits.length !== expect) {
    console.error(`secret-scan: FAIL - expected ${expect} hit(s), found ${hits.length} across ${filesScanned} file(s)`);
    for (const h of hits) console.error(`  ${h.rule}  ${h.file}`);
    process.exit(1);
  }
  if (staleAllow.length) {
    console.error(`secret-scan: FAIL - stale exemption(s) matching nothing: ${staleAllow.join(", ")}`);
    process.exit(1);
  }
  console.log(`secret-scan: OK - ${hits.length} hit(s) as expected, ${filesScanned} ${mode} file(s) scanned`);
}
