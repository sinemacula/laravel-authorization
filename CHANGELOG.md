# Changelog

## 0.1.0 (2026-11-21)

First release. Role-based access control and IAM-style policy evaluation for Laravel: roles and permissions granted to
any Eloquent model, policy documents that allow or deny actions on resources under conditions, and one evaluator that
combines them.

### Features

* roles and permissions granted in a tenant, optionally limited to an application, with expiry, and reaching the tenants below through a tenant tree
* policy documents in an operator-first language, attached to roles, resources or grantees and validated on write
* one evaluator that decides every check in stages, where a deny always wins, capped by permission boundaries, session policies and tenant guardrails
* decisions with a reason and a trace, explained from code or the console
* Laravel Gate integration through one hook, with `cannot`, `any` and `all`, a trait for policy classes, middleware and Blade directives
* batch checks, `permissionsFor()` and Eloquent query scopes limited to the rows a subject may see
* conditions over a namespaced context built from trusted sources, and attributes from declared providers
* permissions that require a level of authentication, decided through a requirement checker
* delegated administration, decided by what a change hands out and to whom
* break-glass access that is activated, surrendered and revoked, with events for each step
* mutually exclusive roles, refused on every write
* management services for every write, with change events after commit that name the actor
* access reviews that list grant routes, page, stream and export as JSON Lines, with optional usage tracking
* a versioned resolution cache, and per-request state reset between units of work
* pruning of expired grants, a permission catalogue sync command and an import from Spatie's permission tables
* `authorization:check`, settings validated fail closed, a table name prefix, a fake tenant tree and test assertions
