/**
 * Quartum project identity — the reference standard for target verdicts.
 *
 * PUBLIC BY DESIGN. A Supabase project ref is not a secret: it appears in every client
 * URL the products ship. What is secret is the KEY, and no key ever appears in this
 * repository. See README.md for the full public/never-public contract.
 *
 * The primary control is an ALLOWLIST — a credentialled test runs only against a target
 * this repository's operator has declared as staging. A blocklist alone would be wrong
 * the moment someone creates a project nobody remembered to add. The lists below exist
 * so a refusal can say WHICH production system it found, instead of "unknown target".
 */

/** Live projects. Nothing in a test run may resolve to either. */
export const PRODUCTION_REFS = Object.freeze({
  mnvviyiqawwtnwewzmwf: "Project A — Studio + Atlas registry (rights, catalogue)",
  zdqodrkekwkfuqrlfxmq: "Project B-new — Learning clinical data (patients, results)",
});

/** Retired projects. Pointing a test at a cold archive is a bug too. */
export const RETIRED_REFS = Object.freeze({
  sfuxmkxqwuvfbwcfdxrl: "retired Learning project (cold archive)",
  htkissuqpqndkgbhpkby: "retired Project C",
  ojrqbrwlldtgyaxxxils: "retired Lovable Cloud project",
});

export const REF_VARS = Object.freeze([
  "SUPABASE_PROJECT_ID", "VITE_SUPABASE_PROJECT_ID",
  "STAGING_A_PROJECT_ID", "STAGING_B_PROJECT_ID", "QUARTUM_DEMO_SUPABASE_PROJECT_ID",
]);
export const URL_VARS = Object.freeze([
  "SUPABASE_URL", "VITE_SUPABASE_URL",
  "STAGING_A_URL", "STAGING_B_URL", "ATLAS_REGISTRY_URL",
]);
export const JWT_VARS = Object.freeze([
  "SB_SERVICE_ROLE_SECRET_KEY", "SUPABASE_SERVICE_ROLE_KEY", "QUARTUM_SUPABASE_SERVICE_ROLE_KEY",
  "STAGING_A_SERVICE_ROLE_KEY", "STAGING_B_SERVICE_ROLE_KEY",
  "SUPABASE_PUBLISHABLE_KEY", "VITE_SUPABASE_PUBLISHABLE_KEY",
]);

/** Credential NAMES worth scanning for. Names, never values. */
export const CREDENTIAL_NAME_PATTERNS = Object.freeze([
  "SERVICE_ROLE_KEY", "SECRET_KEY", "API_KEY", "WEBHOOK_SECRET", "CRON_SECRET",
  "ATLAS_IMPORT_SECRET",
]);

export function refFromUrl(url) {
  const m = /^https:\/\/([a-z0-9]{20})\.supabase\.co/.exec(String(url || "").trim());
  return m ? m[1] : null;
}

/** Supabase JWTs carry the project ref in the `ref` claim — the one source a variable cannot fake. */
export function refFromJwt(token) {
  const parts = String(token || "").trim().split(".");
  if (parts.length !== 3) return null;
  try {
    const json = JSON.parse(
      Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"),
    );
    return typeof json.ref === "string" ? json.ref : null;
  } catch {
    return null;
  }
}

export function collectRefs(env) {
  const found = [];
  for (const v of REF_VARS) if (env[v]) found.push({ source: v, ref: String(env[v]).trim(), how: "explicit id" });
  for (const v of URL_VARS) { const r = refFromUrl(env[v]); if (r) found.push({ source: v, ref: r, how: "url" }); }
  for (const v of JWT_VARS) { const r = refFromJwt(env[v]); if (r) found.push({ source: v, ref: r, how: "jwt ref claim" }); }
  return found;
}

/**
 * The decision. `allow` is the caller's declared staging allowlist.
 *
 * Fail-closed in every direction: a production ref refuses, a retired ref refuses, a ref
 * that is simply not on the allowlist refuses, and NO configured target at all refuses.
 * Exiting 0 on "nothing to check" is the vacuity this whole workstream exists to delete.
 */
export function evaluateTarget(env, allow = []) {
  const allowed = new Set(allow.filter(Boolean).map((s) => String(s).trim()));
  const refs = collectRefs(env);
  const violations = [];
  for (const f of refs) {
    if (PRODUCTION_REFS[f.ref]) violations.push({ ...f, why: `PRODUCTION — ${PRODUCTION_REFS[f.ref]}` });
    else if (RETIRED_REFS[f.ref]) violations.push({ ...f, why: `RETIRED — ${RETIRED_REFS[f.ref]}` });
    else if (!allowed.has(f.ref)) violations.push({ ...f, why: "NOT ON THE STAGING ALLOWLIST" });
  }
  const configured = refs.length > 0;
  return { refs, violations, configured, permitted: configured && violations.length === 0 };
}
