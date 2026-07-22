---
name: Incorrect Check / Template Match Report
about: A check or template match is reporting Present, Missing, or Partial incorrectly
title: '🐛 Incorrect check result — [CHECK NAME]'
labels: bug, template-matching, needs-triage
assignees: ''
---

## 🐛 Incorrect Check / Template Match

### Which check or template is affected?

> Give the exact name as it appears in the Templates or Findings tab.
> e.g. `APP - SESSION - O365 - TimeoutSettings` or `checkMissingMFA`

**Check / Template name:**

---

### What result are you seeing?

- [ ] **Present** (100 % or near 100 % — but the policy doesn't actually satisfy the requirement)
- [ ] **Missing** (but I do have a matching policy)
- [ ] **Partial** (wrong confidence %)
- [ ] **Finding raised** (but it's a false positive)
- [ ] **Finding NOT raised** (but it should be)

**Confidence / score shown:**

---

### What result do you expect?

Describe what the correct status should be and why.

---

### Tenant policy details

Provide the **JSON export** of the policy (or policies) involved.
Run this in PowerShell to export a single policy by display name:

```powershell
Get-MgBetaIdentityConditionalAccessPolicy -Filter "displayName eq 'YOUR POLICY NAME'" |
  ConvertTo-Json -Depth 10
```

Or export all policies and trim to the relevant ones:

```powershell
Get-MgBetaIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 10 | Out-File ca-export.json
```

<details>
<summary>Policy JSON</summary>

```json
PASTE JSON HERE
```

</details>

---

### Screenshots

Attach screenshots showing the incorrect result. Include:
1. The **Templates** or **Findings** tab showing the wrong status
2. (Optional) The **Policies** tab showing the actual policy configuration

---

### Environment

- **Source**: Live tenant connection / Offline import
- **Browser**: (e.g. Chrome 126, Edge 125)
- **App version / date**: (e.g. v1.16.1, or just today's date from the hosted app)

---

### Expected behaviour vs actual behaviour

| | Expected | Actual |
|---|---|---|
| **Status** | | |
| **Confidence %** | | |
| **Reason shown** | | |

---

### Additional context

Anything else that helps reproduce the issue (tenant license tier, specific policy settings, named locations involved, etc.).

---

## 🔧 For maintainers — fix checklist

- [ ] Reproduce with the submitted policy JSON
- [ ] Identify the fingerprint field(s) that are missing or over-broad
- [ ] Add / update the fingerprint in `src/data/policy-templates.ts`
- [ ] Add / update the matcher branch in `src/lib/template-matcher.ts`
- [ ] Add a regression fixture in `docs/fixtures/` (copy the minimal policy JSON)
- [ ] Run `npx tsc --noEmit` — no errors
- [ ] Run `npm run build` — clean build
- [ ] Update `CHANGELOG.md` under `### Fixed`
- [ ] Open a PR using the PR template
