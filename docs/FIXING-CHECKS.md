# Fixing Template Checks & Analyzer Findings

This guide covers everything you need to fix an incorrect template match or
analyzer finding, add a regression fixture, and get your change merged.

---

## Quick orientation

| File | What it does |
| --- | --- |
| `src/data/policy-templates.ts` | Defines every built-in template and its **fingerprint** |
| `src/lib/template-matcher.ts` | The **scoring engine** — compares a tenant policy against a fingerprint |
| `src/lib/analyzer.ts` | Individual **analyzer checks** (MFA, legacy auth, exclusions, etc.) |
| `src/components/findings-list.tsx` | Category metadata for the Findings tab |
| `docs/fixtures/` | Minimal policy JSON **regression fixtures** |

---

## 1 — Fixing an incorrect template match

### How scoring works

`scorePolicyMatch()` in `template-matcher.ts` assigns weighted points for each
fingerprint field. The final percentage is `matchedWeight / totalWeight × 100`.
A score ≥ 85 % → **Present**; 70–84 % → **Partial**; < 70 % → **Missing**.

**Common causes of false "Present":**

| Symptom | Root cause | Fix |
| --- | --- | --- |
| Generic all-apps policy matches an app-specific template | App targeting gives full credit when a policy targets "All" apps | Add `requireSpecificApp: true` to the fingerprint |
| A policy without the distinctive session control still matches | Session control not in the fingerprint | Add the relevant `session*` fingerprint field |
| Roles partially overlap but policy still shows Present | Role threshold too low | Lower the `ratio >= 0.5` threshold or tighten fingerprint |

### Step-by-step: fix a template fingerprint

1. **Reproduce** — load the submitted policy JSON using **Offline Mode**
   (drag the JSON into the home screen import box).

2. **Identify the distinguishing control** — what makes this template unique?
   - A specific app ID (SharePoint, AVD, Office 365)?
   - A session control (`applicationEnforcedRestrictions`, `cloudAppSecurity`, SIF)?
   - A location condition? A platform? A risk level?

3. **Add the missing fingerprint field** in `src/data/policy-templates.ts`:

```ts
// Example: template requires app-enforced restrictions session control
fingerprint: {
  includeApps: ["Office365"],
  requireSpecificApp: true,          // don't match broad "All apps" policies
  targetsAllUsers: true,
  sessionApplicationEnforcedRestrictions: true,   // ← distinctive control
},
```

Available fingerprint fields and their scorer weights:

| Field | Weight | Description |
| --- | --- | --- |
| `includeApps` | 25 | App IDs the template targets |
| `requireSpecificApp` | — | When true, "All apps" does NOT satisfy `includeApps` |
| `grantControls` | 25 | Required grant controls (`block`, `mfa`, etc.) |
| `targetsAllUsers` | 15 | Must target `includeUsers: ["All"]` |
| `targetRoles` | 15 | Role template IDs that must be present |
| `usesLocationCondition` | 10 | Policy must configure location conditions |
| `platforms` | 10 | Platform conditions |
| `clientAppTypes` | 10 | Client app types (`browser`, `mobileAppsAndDesktopClients`) |
| `signInRiskLevels` | 20 | Risk level conditions |
| `userRiskLevels` | 20 | User risk level conditions |
| `sessionSignInFrequency` | 10 | Any SIF control enabled |
| `sessionSignInFrequencyEveryTime` | 10 | SIF set to "everyTime" |
| `sessionPersistentBrowser` | 5 | Persistent browser control |
| `sessionCloudAppSecurity` | 15 | MCAS/Defender XDR session control |
| `sessionApplicationEnforcedRestrictions` | 25 | App-enforced restrictions |
| `authenticationFlows` | 15 | Transfer method blocks |
| `targetsGuests` | 15 | Targets `GuestsOrExternalUsers` |
| `targetsAgentIdentities` | 15 | Targets agent service principals |
| `agentIdRiskLevels` | 20 | Agent identity risk levels |

4. **If the scorer doesn't handle the new field** — add a branch in
   `src/lib/template-matcher.ts` inside `scorePolicyMatch()` following the
   existing pattern:

```ts
// ── My new session control (weight: N) ───────────────────────────
if (fingerprint.myNewField) {
  totalWeight += N;
  if (session?.myNewField?.isEnabled) {
    matchedWeight += N;
  } else {
    differences.push("Session: template requires my-new-control, not configured");
  }
}
```

5. **Type-check**: `npx tsc --noEmit` — must exit clean.

---

## 2 — Fixing an incorrect analyzer check

Analyzer checks live in `src/lib/analyzer.ts` as standalone functions called by
`analyzeAllPolicies()`.

### Finding the check

```bash
grep -n "checkYourCheckName\|your finding title text" src/lib/analyzer.ts
```

### Check function template

```typescript
/**
 * Check: [Short name]
 * [What it detects and why it matters]
 *
 * Reference: [MS Learn or CVE URL]
 * Introduced: v[X.Y.Z]
 */
function check[Name](
  policy: ConditionalAccessPolicy,
  context: TenantContext
): Finding[] {
  const findings: Finding[] = [];

  // Skip disabled policies (remove if the check applies to disabled too)
  if (policy.state === "disabled") return findings;

  // Guard — only run where relevant
  const { applications, users } = policy.conditions;
  if (!applications.includeApplications.includes("TARGET_APP_ID")) return findings;

  // --- detection logic ---
  const grant = policy.grantControls;
  const session = policy.sessionControls;

  if (/* gap found */) {
    findings.push({
      id: nextFindingId(),
      policyId: policy.id,
      policyName: policy.displayName,
      severity: "high",          // critical | high | medium | low | info
      category: "Category Name", // must exist in CATEGORY_META
      title: "One-line problem statement",
      description: "Explain the risk in plain English.",
      recommendation: "Concrete step-by-step remediation.",
    });
  }

  return findings;
}
```

### Integration checklist

- [ ] Add the function to `src/lib/analyzer.ts`
- [ ] Wire it into `analyzeAllPolicies()` (search for the call chain ~line 150)
- [ ] If it's a new category: add to `CATEGORY_META` in `src/components/findings-list.tsx`
- [ ] `npx tsc --noEmit` — clean

---

## 3 — Adding a regression fixture

Fixtures prevent the same bug from re-appearing silently.

1. Create a minimal JSON file in `docs/fixtures/` that contains only the
   policy (or policies) that triggered the bug:

```bash
# Export the policy that triggered the wrong match
Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq 'YOUR POLICY'" |
  ConvertTo-Json -Depth 10 | Out-File docs/fixtures/my-check-regression.json
```

2. Name it descriptively:
   - `template-match-sharepoint-nontrusted-false-positive.json`
   - `check-mfa-all-users-report-only.json`

3. In your PR description, note which fixture corresponds to which bug.

---

## 4 — Updating the CHANGELOG

Add your fix under `## [Unreleased]` (create the section if it doesn't exist):

```markdown
## [Unreleased]

### Fixed

- **Template: APP - BLOCK - SharePoint-OneDrive - NonTrustedLocations** —
  Added `requireSpecificApp: true` so broad "All apps" policies (e.g. block-by-IP)
  no longer score 100 % against this SharePoint-specific template.
```

---

## 5 — Commit and PR

- Commit message format: `fix: <short description>`
  - e.g. `fix: require specific app for SharePoint/O365 template fingerprints`
- Keep each fix in its own commit where possible
- Open a PR using the **PR template** — fill in every section

---

## Common pitfalls

- **Do not use `// @ts-ignore`** — fix the types properly.
- **Do not change the 70 % / 85 % Present threshold** without discussion —
  it affects many templates.
- **`requireSpecificApp` is only for app-specific templates** — do not set it
  on general baseline templates (MFA for all users, block legacy auth, etc.)
  where an all-apps policy is a valid match.
- **Weights must stay consistent** — if you add a new field to the scorer,
  document the weight in the table above.
