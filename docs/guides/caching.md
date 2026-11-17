# Caching

Every check reads what its subject's grants resolve to: the roles it holds, the keys of the roles it reaches, its
permissions, its policies and its permission boundaries, with the policies attached to the resource and to its type, and
the guardrails of the scope. The resolution cache keeps these, so a warm check reads none of them from the database; a
policy store, when one is bound, is still asked on every check. It never keeps a decision: each check is decided afresh
from what the cache holds (see [The decision and the exception](context.md#the-decision-and-the-exception)).

## The two tiers

The memo is always on. It is held in memory for one request or job, built afresh for each (see [Octane and long-lived
workers](long-lived-workers.md)), and keyed by kind and grantee alone, so a hit costs no lookup. Its entries hold in one
scope, a tenant, whether checks are decided just below it, and an application, and are dropped when the scope changes; a
[batch of checks](checking-access.md#bulk-checks) keeps each scope's entries apart until it closes. The memo never
compares versions: an entry holds until it lapses, or until a write, `treeChanged()` or `forgetDecisionsFor()` empties
it.

The store is optional: when `cache.store` names a cache store, every entry is written there too, and any worker reads it
back while the versions it recorded hold. A hit costs two reads of the store, the entry and the versions it recorded,
and no query, and is memoised for the rest of its life. Any Laravel store works, with or without tags. An entry is
written only when every version it depends on could be pinned before it was read, the records stayed the same while it
was resolved and the tenant's ancestors did not move; otherwise it is kept in the memo alone. One a write invalidated
while it was resolved is stored with a version that no longer holds, so it is never served.

Every entry, in either tier, lives at most `ttl` seconds, and lapses a second before the nearest expiry of a grant it
counts, so a temporal grant stops counting at its expiry in a long request as well. An entry that has already lapsed is
never stored.

## Settings

```php
'cache' => [
    'store'  => env('AUTHORIZATION_CACHE_STORE'),
    'ttl'    => env('AUTHORIZATION_CACHE_TTL_SECONDS', 300),
    'prefix' => env('AUTHORIZATION_CACHE_PREFIX', 'authorization'),
],
```

- `store` names a store in `cache.stores`, or is null, the default, for the memo alone. A name the cache manager cannot
  build is refused at boot (`unknown_name`).
- `ttl` is a whole number of seconds of at least 1, 300 by default. Null is refused: there is no "forever", so an entry
  that missed an invalidation still lapses.
- `prefix` starts every key the cache writes, a non-empty string. Applications sharing a store are kept apart by it
  alone.

The cache reads the three as it is built, once a request or job, through the checks the boot runs (see [Configuration
checks](configuration.md#configuration-checks)), so a change made at run time is seen from the next request or job.

## Keys and versions

An entry's key names its kind, its grantee and the scope it was built in:

```text
{prefix}:{kind}:{grantee type}:{grantee key}:{scope}
```

The scope is `platform:{application}`, or `{tenant type}:{tenant key}:{application}` with `:below` after the tenant when
checks are decided just below it; the application is `app:{name}`, or `every` for none. The kinds are:

| Kind                                                          | Holds                                                           |
|---------------------------------------------------------------|-----------------------------------------------------------------|
| `roles`, `role-keys`, `permissions`, `policies`, `boundaries` | A grantee's roles, role keys, permissions, policies, boundaries |
| `resource-policies`                                           | The policies attached to a record and to its type               |
| `resource-type-policies`                                      | The policies attached to the type alone (grantee key `*`)       |
| `guardrails`                                                  | The guardrails of the scope (grantee `guardrails:*`)            |

A kind that holds policy documents ends its key with `:limits:` and a fingerprint of the [policy
limits](policies.md#writing-policies): a document is checked against the limits when it is read from the database, not
when it is read from the store, so changing a limit makes every such entry miss. While [grant usage
tracking](access-reviews.md#usage-tracking) is on, `permissions` and `policies` are kept as `permissions-routed` and
`policies-routed`, with the routes of the grants behind them. While [break-glass](break-glass.md) is enabled, entries
are kept under `{prefix}:break-glass` instead, so an entry that counted an activation never reaches a request in which
none counts, nor the reverse.

Each entry records the version of everything it was built from, and holds only while every one is unchanged. A version
is a random token kept in the store under `{prefix}:version:`, which a write bumps by replacing it:

| Version                    | Recorded by                                                      |
|----------------------------|------------------------------------------------------------------|
| `grantee:{type}:{key}`     | Every entry of the grantee                                       |
| `role:{key}`               | Every entry built from the role, its ancestors included          |
| `policy:{key}`             | Every entry built from the policy                                |
| `tenant:{type}:{key}`      | Every entry built in the tenant or below it                      |
| `role-policies`            | Every entry of a grantee's policies                              |
| `resource-policies`        | Every entry of a resource's policies                             |
| `resource-policies:{type}` | Every entry of the policies attached to that type or its records |
| `boundaries`               | Every entry of a grantee's boundaries                            |
| `guardrails`               | Every entry of the guardrails                                    |

The tokens are random rather than counters, so a token the store evicts and creates again never matches an entry
recorded before it. The layout is the package's own: read it to inspect a store, never write to it.

## Invalidation

A write through the package's models and services bumps the versions its events name:

| Write                                                                            | Bumps                                                         |
|----------------------------------------------------------------------------------|---------------------------------------------------------------|
| A grant to a grantee, its revocation or expiry, a boundary set or removed        | The grantee's                                                 |
| A policy attached to, detached from or expiring on a role                        | The role's `grantee:` version and `role-policies`             |
| A role's permissions or their expiry, its parent, name or owner, or its deletion | The role's                                                    |
| A policy changed or deleted                                                      | The policy's, `resource-policies`, `boundaries`, `guardrails` |
| A guardrail set or removed                                                       | `guardrails`                                                  |
| A policy attached to or detached from a resource                                 | `resource-policies:{type}`                                    |
| A permission deleted, renamed or moved to another owner                          | Each role and grantee holding it                              |
| A break-glass activation written or ended                                        | Its grantee's                                                 |
| `Authorization::treeChanged($tenant)`                                            | The tenant's                                                  |

A record created changes nothing until it is granted, which is a write of its own. A row written past the package, by
the query builder, raw SQL or another system, bumps nothing, and the entries built from it hold until they lapse.

The versions are bumped inside the write's transaction on the package's connection, again once it commits, before any
listener of its events runs, and again if it rolls back. A check that stored an entry from the rows before the commit,
or from rows a rollback discards, recorded a version that no longer holds, so its entry is never served. A write made
with no transaction open on that connection has already committed, and is bumped at once and again.

The worker that wrote empties its memo at once, so its next check reads afresh. Every other worker reads the change from
its next request or job; one already running keeps what its memo holds until each entry lapses, `ttl` seconds at most,
unless it forgets it (see [Long-running commands](long-lived-workers.md#long-running-commands)). Without a store,
invalidating empties the memo and nothing else.

## Tree changes

The tenant tree is the application's, so the package learns of a change to it only when told. Once a tenant has moved
under another parent, or been deleted, report it:

```php
Authorization::treeChanged($account);
```

It takes the tenant as a model, an `AuthorizableTenant` or a `Reference`. It empties the memo and bumps the tenant's
version, which every entry built in the tenant or below it records, so the move takes effect on the next check in the
worker that reports it, and from the next request or job in every other. It also drops the tenant resolved for the
request, so its ancestors are read again, and a delegated administration call running meanwhile is tried again rather
than written on the chains its decisions read (see [Delegated
administration](administration.md#delegated-administration)). Like a write, the version is bumped again once an open
transaction commits or rolls back. A change not reported is seen only by a later request or job, once the entries built
under the old tree have lapsed. Reporting runs no grant hook: an integration that widens a scope on a move asks the
[grant scope query](administration.md#grant-scope-query) whose grants the move concerns.

## A failing store

A store that throws on a read or write is never fatal to a check. The failure is written to the log channel, the store
is not used again for the rest of the request or job, and checks read the database. A stored value without the shape of
an entry is resolved again, and an entry whose contents cannot be decoded is discarded with a warning and resolved
again.

Invalidation is stricter. A bump that throws inside a write's transaction is not caught, so the write rolls back rather
than commit with entries that still allow what it took away: while the store cannot be written, writes through the
package fail. A write made with no transaction open has already committed, and the first bump's failure is still thrown.
A bump once the write has committed cannot undo it, so its failure is written to the log channel. `treeChanged()` throws
a failure of the store, so the caller can try again.

## Example: a revocation across workers

Two applications share one Redis store, each with its own prefix:

```dotenv
AUTHORIZATION_CACHE_STORE=redis
AUTHORIZATION_CACHE_TTL_SECONDS=600
AUTHORIZATION_CACHE_PREFIX=admin-authorization
```

User 42 (morph type `user`) is signed in on the `web` guard, so the shipped subject resolver puts it at platform scope
on the `web` application. Its first check in worker A misses both tiers, reads the database, and stores its entries, the
permissions entry recording the versions of the user and of each role it reaches:

```php
Authorization::can('posts:update'); // worker A: admin-authorization:permissions:user:42:platform:app:web stored
Authorization::can('posts:update'); // worker A, same request: read from the memo
Authorization::can('posts:update'); // worker B, next request: read from the store, versions compared
```

An administrator revokes the role in worker C:

```php
$user->revokeRole('editor');
```

The grant service bumps `admin-authorization:version:grantee:user:42` inside its transaction and again once it commits,
then dispatches `Identity\RoleRevoked`. Worker C's next check reads the database. Worker A's and worker B's next
requests find the recorded version changed, read the database and store a fresh entry. A queued job already running in
worker D, which checked the user before the revocation, keeps its memo entry until it lapses, at most 600 seconds after
it was resolved.
