## Summary

<!-- One sentence: what does this PR fix or add? -->

## Type of change

- [ ] 🐛 Bug fix — incorrect check / template match result
- [ ] ✨ New check or template
- [ ] 🔧 Improvement to existing check / scoring logic
- [ ] 📖 Docs / CHANGELOG only
- [ ] 🔨 Refactor / tech debt

---

## What check or template does this affect?

> Name the specific check function or template (e.g. `APP - SESSION - O365 - TimeoutSettings`,
> `checkMissingMFA`, `APP - BLOCK - SharePoint-OneDrive - NonTrustedLocations`).

---

## Root cause (for bug fixes)

Explain *why* the check was producing the wrong result before this change.

---

## What changed

Describe every file touched and why:

| File | What changed |
| --- | --- |
| `src/data/policy-templates.ts` | |
| `src/lib/template-matcher.ts` | |
| `src/lib/analyzer.ts` | |
| `docs/fixtures/` | |
| `CHANGELOG.md` | |

---

## Before / after

| | Before | After |
| --- | --- | --- |
| **Status shown** | | |
| **Confidence %** | | |
| **Policy used to test** | | |

> Attach screenshots if applicable.

---

## Checklist

### Code quality

- [ ] `npx tsc --noEmit` passes — no TypeScript errors
- [ ] `npm run build` succeeds
- [ ] No `// @ts-ignore` or `any` casts added

### Template / check changes

- [ ] Fingerprint fields documented in `docs/FIXING-CHECKS.md` weight table (if new field added)
- [ ] `requireSpecificApp` only set on app-specific templates — not on general baseline templates
- [ ] New scorer branch follows the `totalWeight += N / matchedWeight += N` pattern
- [ ] New `differences.push(...)` message is user-readable (shows in the UI tooltip)

### Regression

- [ ] Minimal policy JSON fixture added to `docs/fixtures/` (name matches the bug)
- [ ] Fixture verified to reproduce the original wrong result on `main`
- [ ] Fix confirmed to resolve the wrong result

### Docs

- [ ] `CHANGELOG.md` updated under `### Fixed` or `### Added`
- [ ] If a new category is added: `CATEGORY_META` updated in `src/components/findings-list.tsx`

---

## Linked issue

Closes #

---

## Screenshots

<!-- Attach before/after screenshots from the Templates or Findings tab -->
