#!/usr/bin/env node
/**
 * Production-target interlock — CI entry point.
 *
 * Refuses unless every project reference resolvable from the environment is on the
 * declared staging allowlist. Fail-closed in both directions: a production or retired
 * ref refuses, and NO configured target refuses too.
 *
 * Import-safe: everything above the CLI guard at the bottom is pure. A test that imports
 * this to reuse `evaluateTarget` must not have the process exit underneath it.
 *
 *   node src/assert-not-production.mjs             enforce against the environment
 *   node src/assert-not-production.mjs --self-test replay the published vectors
 *
 * Allowlist comes from QUARTUM_STAGING_ALLOW (comma-separated project refs).
 */
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { evaluateTarget, PRODUCTION_REFS, RETIRED_REFS } from "./project-refs.mjs";

export { evaluateTarget, PRODUCTION_REFS, RETIRED_REFS };

const HERE = dirname(fileURLToPath(import.meta.url));

/** Mint an unsigned JWT carrying only a `ref` claim. Authenticates nothing. */
export function fabricateJwt(ref) {
  const payload = Buffer.from(JSON.stringify({ ref, role: "service_role" })).toString("base64url");
  return `eyJhbGciOiJIUzI1NiJ9.${payload}.not-a-real-signature`;
}

/** Expand @@JWT:ref@@ placeholders so no token literal is stored in the vectors. */
function hydrate(env) {
  const out = {};
  for (const [k, v] of Object.entries(env)) {
    const m = /^@@JWT:([a-z0-9]+)@@$/.exec(String(v));
    out[k] = m ? fabricateJwt(m[1]) : v;
  }
  return out;
}

export function runVectors() {
  const spec = JSON.parse(readFileSync(join(HERE, "..", "vectors", "target-verdicts.json"), "utf8"));
  const results = spec.cases.map((c) => {
    const got = evaluateTarget(hydrate(c.env), spec.stagingAllowlist).permitted;
    return { name: c.name, want: c.permitted, got, ok: got === c.permitted };
  });
  return { results, allowlist: spec.stagingAllowlist };
}

function selfTest() {
  const { results } = runVectors();
  console.log("\nPRODUCTION-TARGET INTERLOCK — published vectors\n" + "=".repeat(78));
  for (const r of results) {
    console.log(
      `${r.ok ? " ok " : "FAIL"}  expect=${r.want ? "permit" : "refuse"}  ` +
        `got=${r.got ? "permit" : "refuse"}  ${r.name}`,
    );
  }
  const bad = results.filter((r) => !r.ok).length;
  console.log("=".repeat(78));
  console.log(`${results.length - bad}/${results.length} target-verdict vectors passed`);
  process.exit(bad ? 1 : 0);
}

function enforce() {
  const allow = (process.env.QUARTUM_STAGING_ALLOW ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const { refs, violations, configured } = evaluateTarget(process.env, allow);
  if (!configured) {
    console.error(
      "\nREFUSING — no Supabase project is configured.\n\n" +
        "A credentialled job with no target must FAIL, not pass green.\n",
    );
    process.exit(1);
  }
  if (violations.length) {
    console.error("\nREFUSING — a target outside the staging allowlist is in scope.\n");
    for (const v of violations) console.error(`  ${v.source} (${v.how}) -> ${v.ref}\n    ${v.why}`);
    console.error(`\nAllowlist: ${allow.length ? allow.join(", ") : "(empty — nothing is permitted)"}\n`);
    process.exit(1);
  }
  console.log("assert-not-production: ok");
  for (const r of refs) console.log(`  ${r.source} (${r.how}) -> ${r.ref}`);
}

// The ONLY side effect, and only when run as a program.
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  if (process.argv.includes("--self-test")) selfTest();
  else enforce();
}
