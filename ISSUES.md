# `sinemacula/laravel-authorization` — Open Issues

**Source of truth for v1.0 scope.** Every item listed here is in scope for
the initial release. Historical references to `SPECS.md` / the PRD remain
inline where they add design context; the documents themselves have been
consumed into this file and removed from the repo.

---

## `README.md` is the wrong package's README

**Where:** `README.md` at repo root.

**Current shape:** the heading, badges, feature list, quick-start sections, and
design-note citations are all about `sinemacula/laravel-authentication` (the
sibling package) — not this package. Almost certainly a copy that was never
updated after the repo was split.

**Fix:** rewrite the README for `sinemacula/laravel-authorization`. The new
README should cover: the RBAC + AWS-IAM-style policy model, the four-step
evaluator (explicit deny → allow → RBAC → implicit deny), the enum-as-source-
of-truth catalogue (`permission_enums` config, `#[Permission]` attribute,
`authorization:sync`), the tenant-scope hook, the Gate / facade / middleware /
Blade surface, and a link into `docs/design/` for the authoritative notes.

Use the existing `README.md` as a layout template (badges, feature bullets,
installation, quick start) but replace every mention of JWT guards, devices,
refresh tokens, and principal contextualisation with authorization content.

**Scope:** `README.md` only. The `docs/design/` notes are correct.
