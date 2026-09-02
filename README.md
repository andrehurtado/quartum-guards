# quartum-guards

Fail-closed safety controls for the Quartum platform, consumed as a pinned GitHub Action
by three private repositories.

## Why this repository is public, and separate

The three Quartum applications are private, live under two different GitHub owners, and
share no monorepo or package registry. The obvious alternative — copying the guard scripts
into each repository — was tried and rejected on evidence:

> A scanner that computes its own scan root from its file location was copied into another
> repository. The directories it searched did not exist there, so it found nothing, printed
> `clean across 3 repo(s)` and exited 0 — permanently. The integrity check meant to catch
> tampering compared the copy against its own fingerprint, so a faithful-but-useless copy
> passed it.

That is an assay reporting a clean result because no sample ever reached the instrument,
with the QC step blind to it. One public Action removes the class: a single instance, in its
own layout, with no copies to drift. A public repository is consumable by private ones with
no token, which a private one is not.

## What is here, and what may never be

**Here, by design**

- guard logic
- Supabase project identifiers — a project ref is not a secret; it appears in every client
  URL the products ship
- credential *name* patterns (`ATLAS_IMPORT_SECRET`, `SERVICE_ROLE_KEY`, …)
- fabricated fixtures and reference vectors

**Never here, under any circumstances**

- a real service-role key
- a real JWT
- a real private key
- an environment file
- patient or clinical data, or protected clinical test content

Every credential in this repository is synthetic. The JWTs are unsigned, carry only a `ref`
claim, and authenticate nothing.

## The rule

An allowlist, not a blocklist:

```
credentialled test or job wants to run
        ↓
resolve the ACTUAL target from id, URL, and the ref claim inside the credential
        ↓
is every resolved ref on the declared staging allowlist?
   YES → permitted
   NO  → refuse, naming what was found
```

A blocklist alone is wrong the moment someone creates a project nobody remembered to add.
The production and retired lists exist so a refusal can say *which* live system it found
rather than "unknown target". **No configured target at all also refuses** — exiting 0 on
"nothing to check" is the vacuity these controls exist to delete.

## Usage — pin to a full commit SHA

```yaml
- uses: andrehurtado/quartum-guards@<full-40-character-commit-sha>
  with:
    scan-root: .
```

Never `@main`. Never a tag. A tag is mutable by whoever owns this repository; pinning to a
tag would make a public dependency a supply-chain hole rather than a guard.

## Reference vectors

`vectors/target-verdicts.json` is the reference standard. Each consuming repository has its
own small implementation of the refusal rule and proves itself against these vectors.
Independent implementations agreeing on a published reference set is a stronger property
than identical copies of one file — the argument this platform already makes for its shared
scoring engine.

## Self-checks

```bash
node src/assert-not-production.mjs --self-test   # replays the published vectors
node src/secret-scan.mjs --self-test             # positive control: must find EXACTLY 4
node src/secret-scan.mjs <root>                  # a real tree: must find 0
```
