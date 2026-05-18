# DR19 — deferred items

DR19 (`plan/08-dr/dr19-release.md`) shipped these §12 controls in the v1.2.0.x
cutover commit:

- §12.2 — signing-cert SHA-256 pin + `apksigner` assertion in `release.yml`
- §12.3 (interim) — `classes*.dex` SHA-256 witnesses in the release body
- §12.5 — proguard `com.voicedrop.crypto.**` reflection-allowance grep (CI + release)
- §12.6 — manifest invariants (already covered by `ManifestInvariantTest` from DR1)
- §12.8 — `ratchetLint` gradle task wired into `:app:check`

The items below need an online CI bootstrap (or a follow-up build) before they
can be turned on. None of them gate the v1.2.0.x ratchet release: they are
supply-chain belts on top of an already-controlled build, not new attack
surface.

## §12.1 — Gradle dependency verification (`gradle/verification-metadata.xml`)

**Status:** not enabled.

**Why deferred:** generating the SHA-256 hashes requires Gradle to resolve every
transitive dependency from Maven Central / Google's Maven, which is not
possible in the offline sandbox where the v1.2.0.x cutover commits were
authored.

**Bootstrap recipe (one-off PR):**

```bash
./gradlew --write-verification-metadata sha256 help
git add gradle/verification-metadata.xml
git commit -m "ci: pin transitive deps via verification-metadata.xml (DR19 §12.1)"
```

After merging, every dependency change must come with a verification-metadata
update; CI will fail otherwise. Dependabot PRs need both files in the diff.

## §12.3 — full reproducible build

**Status:** partial — dex SHA-256 witnesses are emitted in the release body
(`Build integrity` section). Two consecutive builds are not yet compared.

**Why deferred:** a hard reproducibility check would block the release on the
first build-environment non-determinism it finds. Real reproducibility needs
`SOURCE_DATE_EPOCH`, deterministic `zipalign` ordering, and AGP / KSP /
Kotlin-compiler determinism flags that have not been audited end-to-end.

**Follow-up:** a separate CI job that runs `assembleRelease` twice with
`SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)` and `diff -r` on the unpacked
APK contents (excluding `META-INF/`). Iterate on flagged non-determinism until
the diff is empty, then promote the job from advisory to gating.

## §12.4 — GitHub Actions SHA pinning

**Status:** `actions/checkout`, `actions/setup-java`, `actions/upload-artifact`,
`softprops/action-gh-release` are still pinned to tags (`@v4`, `@v2`), not 40-character commit SHAs.

**Why deferred:** pinning needs the canonical commit SHA for each action's
released tag — those are pulled from GitHub. The offline sandbox can't resolve
them, and pinning to invented SHAs is worse than tag-pinning.

**Follow-up recipe (one-off PR):**

For each `uses: org/repo@vN` in `.github/workflows/*.yml`:

```bash
gh api repos/<org>/<repo>/git/ref/tags/<tag> --jq '.object.sha'
```

Substitute the resulting SHA. Keep the `# vN` comment on the same line for
human-readable diffing of dependabot-style upgrade PRs:

```yaml
uses: actions/checkout@<40-char-sha>  # v4.2.2
```

## §12.7 — build-time schema-hash diff

**Status:** runtime schema integrity is enforced by Room's own
`identity_hash` check (built into every Room-generated `RoomOpenHelper`).
Schema-JSON drift is not yet enforced at CI level.

**Why deferred:** Room writes `app/schemas/com.voicedrop.storage.AppDatabase/3.json`
during the KSP step; we haven't committed that file because the v1.2.0.x
cutover happened in the offline sandbox. Once it's checked in, a CI step like:

```yaml
- name: Assert Room schema is committed
  run: |
    ./gradlew :app:compileDebugKotlin
    git diff --exit-code app/schemas
```

would catch any DB entity change that wasn't accompanied by a `versionCode`
bump + migration plan. Land alongside the §12.1 bootstrap.
