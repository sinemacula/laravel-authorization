# Policies

How a check is decided, how a policy document is written, and how a policy is attached to an identity, a role or a
resource.

## How a check is decided

`Authorization::check()` is the one decision behind `can()`, `cannot()`, `any()`, `all()`, `authorize()`, `explain()`,
the Gate, a Laravel policy class deciding through the package's trait, the `permission:` and `authorize:` middleware and
the permission directives (`role:` and `@role` check membership only, so no stage applies to them, guardrails and
boundaries included). It runs these stages in order, and the first that decides ends it, except that the
administration stage can still refuse an allow; no allow is weighed before every deny and every cap has run:

| Stage            | What it weighs                                                                                                    | Denies as                                                                                                                                                                                                                     |
|------------------|-------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `subject`        | Whether there is a subject, and whether it and its identity are active                                            | `subject_unresolved`, `subject_inactive`                                                                                                                                                                                      |
| `resource`       | Whether the resource argument can be identified                                                                   | `resource_unresolved`                                                                                                                                                                                                         |
| `tenant`         | Whether the resource's tenant is within the check's, or a platform-wide grant of the permission admits it         | `tenant_scope`                                                                                                                                                                                                                |
| `deny`           | Every deny: the subject's, its identity's of either kind, their roles', the resource's, guardrails', boundaries'  | `explicit_deny`, `invalid_policy`                                                                                                                                                                                             |
| `guardrail`      | Every guardrail on the check's tenant, its ancestors and the platform must allow the check, unless it is exempt   | `guardrail`, `invalid_policy`                                                                                                                                                                                                 |
| `boundary`       | Every permission boundary of the principal and of its identity that applies must allow the check                  | `boundary`, `invalid_policy`                                                                                                                                                                                                  |
| `session`        | Every session cap, the credential's scopes and each set of actions `capped()` was given, must cover the action    | `session_policy`                                                                                                                                                                                                              |
| `allow`          | Every allow statement that applies to the subject, a resource policy's naming it included, then a permission held | `invalid_policy`                                                                                                                                                                                                              |
| `administration` | The operation's constraints, for an administration action on its own operation resource; refuses only             | `administration.scope`, `administration.rank_uncomparable`, `administration.rank`, `administration.self`, `administration.owner`, `administration.not_grantable`, `administration.unprovable`, `administration.impersonating` |
| `implicit`       | Nothing allowed                                                                                                   | `insufficient_authentication`, `condition_failed`, `no_match`                                                                                                                                                                 |

Within each stage, the policies are assessed in a fixed order (name, stored key, resource, then document) and each
statement by its position, so the decision and its trace never depend on the order the policies were read in. The
decision records the stage that decided it and every step it took: each statement assessed, each guardrail and boundary
that refused the check as `refused`, naming it, each session cap as `covered` or `refused`, naming it, a cap stage that
capped nothing as `uncapped`, the guardrail stage as `exempt` for a check of `authorization:guardrail.manage`, whose
deny stage weighs no guardrail's denies either, the permission step, which is asked only when no allow statement
matched and none was invalid, and the administration stage as `satisfied` when the operation's constraints hold, or
`refused`, naming the reason, when one does not:

```text
DENY (boundary: a permission boundary does not allow it) at the boundary stage.
  [deny] support-read-only[<key>]#1 sid="no-exports": not_applicable
  [guardrail] guardrails: uncapped
  [boundary] support-read-only[<key>]#0 sid="read": not_applicable
  [boundary] support-read-only[<key>]: refused
```

The full contract, and why a deny and a cap always win, is in [Evaluation order and deny
precedence](../design/evaluation-order-and-deny-precedence.md).

### Permissions held and the resources they reach

A permission held, directly or through a role, is one allow source among the others, weighed at the `allow` stage
alone: never before every deny, guardrail, boundary and session cap has let the check through, and only once no allow
statement matched. Nothing answers a check from the permissions before then, so a deny or a cap always beats a
permission held, a `*` included. The permission step names the held permission that allowed, as it was granted, so a
wildcard says which pattern let the action through:

```text
ALLOW at the allow stage.
  [guardrail] guardrails: uncapped
  [boundary] boundaries: uncapped
  [session] session caps: uncapped
  [allow] permission "posts:*": held
```

The subject's own permissions are read first and its granting identity's only when none of the subject's covers the
action; within that grantee, the action itself is named when held, else the first covering pattern in byte order, so
the trace is the same whatever order the grants were read in.

A permission allows a check on a resource only when the grant it came from reaches the resource:

- A resource of a tenant: a grant made in that tenant, a grant made in one of its ancestors that reaches the tenants
  below it (`includeSubtree`, the default), or a platform-wide grant. The resource must still be within the active
  tenant, or below it, to be decided at all; one of any other tenant is denied as `tenant_scope` unless a platform-wide
  grant of the permission admits it, and then only platform-wide grants count, while that tenant's guardrails and the
  denies attached to the resource there still apply.
- A resource with no tenant, a type alone, an opaque identifier or no resource: the grants that hold in the active
  tenant, its own, its ancestors' that reach below and platform-wide ones; with no active tenant, platform-wide grants
  alone.

A grant limited to an application counts only in checks on that application, and an expired grant counts nowhere, for
every kind of resource. A permission held in tenant A therefore allows actions on resources in A and, when the grant
reaches its subtree, in the tenants below A, and never in a sibling of A or in another tree.

The grants are resolved for each scope a check is decided in and kept per scope (tenant and application) in the
resolution cache, so the reach costs no query of its own: once each scope is warm, checks on its resources read none.

The Gate, the `permission:` and `authorize:` middleware and the permission directives all decide through `check()`,
and the bulk checks and `permissionsFor()` decide as it does, so they answer what the decision allows, with every
stage above. `hasPermission()` (and its alias `hasPermissionTo()`), `getPermissions()` and `assertHasPermission()` keep
their meaning: they report what is granted in the current scope and decide nothing, so a permission held that a deny or
a cap refuses is still reported as held.

## Writing policies

A policy document is a `version` (1, the default) and a list of `statements`. Each statement takes:

| Key             | Holds                                                                                     |
|-----------------|-------------------------------------------------------------------------------------------|
| `sid`           | Optional: 1 to 64 letters, digits, `_`, `-`, `:` or `.`, unique within the policy         |
| `effect`        | `allow` or `deny`                                                                         |
| `actions`       | The action patterns the statement names                                                   |
| `not_actions`   | Instead of `actions`: the statement names every action none of these patterns matches     |
| `resources`     | Optional: the resource patterns the statement names                                       |
| `not_resources` | Instead of `resources`: the statement names every resource none of these patterns matches |
| `principals`    | An allow in a resource policy only: whom it applies to, by reference or `role:<role id>`  |
| `conditions`    | Optional: a map of operator to context key path to operand, every test of which must hold |

A statement takes exactly one of `actions` and `not_actions`, and at most one of `resources` and `not_resources`; each
is a non-empty list of non-empty strings. Without either resource list a statement names every resource and a check that
names none. `not_resources` still scopes the statement to resources, so it never covers a check without one. The `sid`
names the statement in the decision and the trace, and never changes how it is evaluated. `principals` belongs to the
allow statements of a policy attached to a resource, and to nothing else (see [Resource-based
policies](#resource-based-policies)).

Conditions name the operator first, then each context key it tests, as a dot path into the check's context:

```php
'conditions' => [
    'ip_in'        => ['request.ip' => ['10.0.0.0/8', '2001:db8::/32']],
    'eq'           => ['resource.owner.id' => '${subject.id}'],
    'any_value_in' => ['input.groups' => ['editors', 'admins']],
    'null'         => ['input.post.archived_at' => true],
    'before'       => ['environment.time' => '2026-12-31T23:59:59Z'],
],
```

| Operator                        | Operand                               | Holds when the context value                                   |
|---------------------------------|---------------------------------------|----------------------------------------------------------------|
| `eq`, `neq`                     | one scalar                            | is a scalar or null that is, or is not, strictly equal to it   |
| `in`, `not_in`                  | a non-empty list of scalars           | is a scalar or null that is, or is not, in the list (strictly) |
| `starts_with`, `ends_with`      | a non-empty string                    | is a string that starts, or ends, with it                      |
| `like`                          | a non-empty glob                      | is a string that matches it                                    |
| `gt`, `gte`, `lt`, `lte`        | a number or numeric string            | is a number above, at least, below or at most it               |
| `before`, `after`               | a time                                | is a time before, or after, it                                 |
| `between`                       | a pair of times                       | is a time within them, inclusive                               |
| `bool`                          | `true`, `false`, `1`, `0`, `'true'` … | has the same boolean meaning                                   |
| `null`                          | `true` or `false`                     | `true`: is missing or null; `false`: is present and not null   |
| `ip_in`, `ip_not_in`            | an address or range, or a list        | is an IPv4 or IPv6 address within any, or within none, of them |
| `any_value_in`, `all_values_in` | a non-empty list of scalars           | is a list with some element, or only elements, in it           |

- A condition key is a dot path read one segment at a time, never a literal key: `input.post.status` reads the
  `status` of the `post` of `input`, and a caller passing `['post.status' => 'draft']` supplies a key named
  `post.status`, which the path never reaches.
- A key the context lacks makes a test undecidable: an allow does not apply and a deny does. `null` decides a missing
  key instead, and any other operator but `authentication_requirement` takes the `_if_exists` suffix (`ip_in_if_exists`,
  `eq_if_exists`), under which a missing key passes; everything else is decided as without it.
- A context value that is not an IP address is undecidable for `ip_in` and `ip_not_in`, so `ip_not_in` never treats
  an unreadable address as outside every range. PHP's `FILTER_VALIDATE_IP` decides what an address is, on every
  platform, so a zone id (`fe80::1%en0`) or an IPv4 part with a leading zero (`010.0.0.1`) is not one.
- A NUL byte is refused in a `starts_with`, `ends_with`, `like` or time operand and in a resource pattern, and a
  context value holding one is undecidable for them and for `ip_in` and `ip_not_in`. A `${…}` value holding one leaves
  a resource pattern unresolved.
- `any_value_in` and `all_values_in` need the context value to be a list, such as a token's scopes. An empty list never
  passes `all_values_in`.
- `eq` and `neq` never take a list: use `in` or `not_in`. String operands may use `${…}` interpolation; list operands
  are literal. A reference reads the same dot paths a condition key does, through the same resolver (`${request.ip}`,
  `${input.post.id}`, `${subject.id}`, `${resource.owner.id}`); a missing, null or non-scalar value leaves it
  unresolved, which makes the test undecidable.
- `authentication_requirement` tests only the reserved key `authentication`, and its operand is a requirement rather
  than a value: see [Authentication requirements](context.md#authentication-requirements).

A policy is checked whenever it is saved, through the model or `PolicyService`, and refused with every limit,
context-key and catalogue reason at once, or, for a malformed document, the first structural fault found and any limit
it breaks. The reasons are a malformed document; a condition key or `${…}` reference that the context key catalogue
does not declare; a condition on a key that may not be tested; a condition on, or a `${…}` reference to, an assurance
key; an operator that does not suit the key's type; an
`actions` or `not_actions` pattern that matches no declared permission; or a document over the limits in
`policies.limits` (`AUTHORIZATION_POLICY_DOCUMENT_BYTES`, `_STATEMENTS`, `_CONDITIONS` and `_PATTERN_LENGTH`: 64 KiB of
JSON, 100 statements, 50 key tests a statement and 512 characters a pattern or string operand). The limits are checked
again when a stored policy is read, and the resolution cache keys cached policies by the limits they were checked
under, so lowering one makes the stored policies over it deny as `invalid_policy` until they are fixed. To find them, or
to check policy files before you deploy them:

```bash
php artisan authorization:policy:validate --database
php artisan authorization:policy:validate policies/
```

The [condition semantics note](../design/wildcard-and-condition-semantics.md) has every operand and edge case.

## Role and inline policies

A role takes policies as an identity does, through the same trait methods and `GrantService` calls, and they apply to
whoever holds the role:

```php
$editor->attachPolicy($noDeletesOffNetwork);                  // for every holder of editor
$editor->attachPolicy($businessHours, tenant: $organisation); // only in the organisation
$grants->detachPolicy($editor, $noDeletesOffNetwork);
```

A role's policy applies only where both grants hold: the holder's grant of the role and the role's attachment of the
policy must each hold in the current tenant (or in a tenant above it, when that grant reaches its subtree) and on the
current application, and neither may have expired. A policy attached to a role in one tenant therefore applies to the
role's holders there and nowhere else, and a role granted in one tenant brings none of its policies to another. With
the hierarchy enabled (`hierarchy.enabled`, the default), a role's policies are inherited down the hierarchy exactly as
its permissions are: whoever holds `editor`, whose parent is `author`, gets the policies of both. A deny in a role's
policy is an explicit deny like any other, and wins over every allow and every permission held.

Attaching or detaching a role's policy, or changing its expiry, dispatches the same `Identity\PolicyAttached`,
`Identity\PolicyDetached` and `Identity\PolicyExpiryChanged` events, with the role as the grantee, and takes effect on
the next check for every holder: a change to any role's policy attachments refreshes every identity's cached policies,
and moving a role in the hierarchy refreshes those of the identities that reach it. Deleting a role detaches its
policies, each reported as detached.

An inline policy belongs to one grantee, an identity or a role. It is attached to that grantee alone and is deleted
with it. Create one through the grantee or `PolicyService::createInline()`, which check its document as any policy's
is checked, then attach it in the scope it should hold in:

```php
use SineMacula\Laravel\Authorization\Services\PolicyService;

$document = [
    'statements' => [
        [
            'effect'     => 'deny',
            'actions'    => ['posts:update'],
            'conditions' => ['neq' => ['resource.owner.id' => '${subject.id}']],
        ],
    ],
];

$policy = $user->createInlinePolicy('own-posts-only', $document);

$user->attachPolicy($policy);

// Or through the service, here for a role:
$editors = app(PolicyService::class)->createInline($editor, 'own-posts-only', $document);

$editor->attachPolicy($editors);
```

Creating an inline policy does not attach it. Attaching it to any grantee but the one it belongs to is refused with
`InlinePolicyAttachmentException`, through the trait methods, `GrantService` (a grant or a sync) and a write through a
grantee's `policies()` relation alike. Each reads that grantee from the stored row, so a policy loaded without its
`owner_type` and `owner_id`, or with them changed and not saved, is judged as it is stored, and a policy whose row is
gone is refused with `InvalidGrantTargetException`. Its name is unique among that grantee's inline policies, so two
users can each have an `own-posts-only`, and it never clashes with a managed policy's name. The grantee is held in
`owner_type` and `owner_id`, apart from the policy's tenant: both are set or neither (`InvalidPolicyOwnerException`),
the grantee is fixed once the policy is created (`OwnerChangedException`), and an inline policy is never a system
policy (`SystemInlinePolicyException`). Deleting the grantee deletes its inline policies, each reported as
`Policy\Deleted`, and their attachments with them; a soft-deleted grantee keeps them until it is force-deleted. A
grantee deleted without its model events, such as by a raw query, leaves them behind until `authorization:prune`
deletes them, once it has revoked the grantee's grants. `authorization:policy:validate --database` checks inline
policies with the rest.

A check gathers its policies from four places: the bound policy store (`policy_store`, for policies shipped in code or
kept elsewhere), the identity's own attachments, managed and inline, its roles' policies, and the policies attached to
the check's resource and to its type (see [Resource-based policies](#resource-based-policies)), plus those of a separate
identity, own and role-attached alike (see `docs/design/evaluation-order-and-deny-precedence.md`). A policy attached
both to the identity and to one of its roles counts once. The order they are gathered in never changes the decision:
each stage assesses them by name, then stored key, then the resource a resource policy is attached to, then document.
The grantee's permission boundaries are read apart from them, so a custom resolver never drops them (see [Permission
boundaries](caps.md#permission-boundaries)).

## Resource-based policies

A policy attached to a resource decides who may do what to that resource, whoever holds which permission. It attaches
to one record, or to a whole resource type, through `ResourcePolicyService`, and its statements say whom they apply to:

```php
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;

$sharing = Policy::create([
    'name'     => 'post-42-sharing',
    'document' => [
        'statements' => [
            [
                'sid'        => 'reviewers-read',
                'effect'     => 'allow',
                'actions'    => ['posts:read', 'posts:comment'],
                'principals' => ['user:17', 'role:' . $reviewers->id],
            ],
            [
                'sid'     => 'never-delete',
                'effect'  => 'deny',
                'actions' => ['posts:delete'],
            ],
        ],
    ],
]);

$resources = app(ResourcePolicyService::class);

$resources->attach($sharing, $post);                                // GrantOutcome::GRANTED, on post:42
$resources->attach($archiving, Post::class, tenant: $organisation); // every post, in the organisation
$resources->detach($sharing, $post);                                // 1, the attachments removed

Authorization::for($user)->can('posts:read', $post);    // true for user 17, with no posts:read permission
Authorization::for($admin)->can('posts:delete', $post); // false: the deny applies to everyone
```

The resource is a saved model (that record), a `[type, id]` pair, a `ResourceReference` with a type, a model class (the
whole type) or a morph type as a string (the whole type). A pair names its record without asking the bound resource
tenant resolver, since the call says where the attachment holds, so a pair the resolver cannot place is still attached.
An unsaved model, anything that names no type, a type or key longer than 191 bytes, and a record whose key is `*` (which
a check on the whole type stands for) are refused with `InvalidResourceException`. An attachment holds in a scope
exactly as a grant does: a policy a tenant owns is attached in that tenant, or a tenant below it that the call names,
and naming any other is refused with `GrantScopeMismatchException`; a platform policy is attached in the tenant named,
else platform-wide. It reaches the tenants below its tenant unless `includeSubtree` is false, and holds in the
application named, else in every application. Attaching what is already attached changes nothing and returns
`GrantOutcome::UNCHANGED`, attaching it again with the other reach returns `REACH_CHANGED`, and `detach()` finds the
attachment in the same scope and returns how many it removed. Each call is one transaction and one operation, and
dispatches `Resource\PolicyAttached` or `Resource\PolicyDetached` once it commits, only when it changed something,
carrying the resource's type, its key (null for the whole type), the policy, its name, the scope and the actor. Deleting
the policy removes its attachments with its row. An attachment names its resource by type and key, so deleting the
record leaves it in place: detach it when the record goes, with `detachAll($record)`, which detaches every policy
attached to the record in every scope (never a whole type's), or let `authorization:prune` remove the attachments of
records that no longer exist (see [Console commands](console.md#console-commands)).

A check on a record (a model, a pair, or an `AuthorizableResource` whose reference names one) reads the policies
attached to that record and those attached to its type; a check on the type alone (a model class) reads those attached
to the type; a check on any other string, or on no resource, reads none. A record whose key no attachment can name (one
longer than 191 bytes, say) still reads its type's policies, its denies included. Only the attachments that hold in the
tenant and application the check is decided in count, and a policy attached to the record and to its type counts once.
They are read in one query and cached with the rest of the resolution: attaching or detaching refreshes the cached
entries of the resource's type, and editing or deleting any policy refreshes every cached resource-policy entry.

**Principals.** Every allow statement of a resource policy carries `principals`, a non-empty list of selectors naming
whom it applies to:

- `<morph type>:<id>` names a subject by reference: the subject's principal or its identity, by morph class (under
  your morph map) and key, such as `user:17`.
- `role:<role id>` names whoever holds that role in the tenant and application the check is decided in. It follows the
  role hierarchy: with `hierarchy.enabled`, it also names whoever holds a role below that role, as the role's
  permissions and policies reach them; with the hierarchy disabled, only whoever holds that role itself. The role is
  named by its key, never its name, so a role of the same name that another tenant owns, or the role held for another
  application, names no one. The roles a subject holds are read through the resolution cache, as its roles are, so
  once warm a check that matches a role selector reads no role.

A selector is an exact name, never a pattern: a space, `*` or `${` in one is refused, and each part is 1 to 191 bytes. A
deny statement takes no `principals` (refused when the policy is saved) and applies to everyone checking the resource,
wherever the check is decided. A statement that names principals applies only as part of a resource policy, so the rule
is held at every write:

- Attaching an inline policy to a resource, or a policy with an allow statement that names no principals, is refused
  with `ResourcePolicyException`.
- Attaching a policy whose statements name principals to an identity or a role (the trait methods, `GrantService`, a
  sync and a write through a grantee's `policies()` relation alike) is refused with `ResourcePolicyException`.
- Rewriting an attached policy's document so that it breaks the rule for where it is attached is refused with
  `ResourcePolicyException`. `getPolicyName()` and `getStatements()` (the positions, from zero) say what broke it.

**How a check decides with them.** A resource policy's denies count at the deny stage with every other deny, so one that
matches denies everyone, a subject that holds the permission or an allow in its own policies included. An allow whose
principals name the subject is an allow source like any other, and allows the check without the subject holding any
permission; one whose principals do not name the subject is recorded as `principal_mismatch` and counts for nothing, an
unmet authentication requirement on it included. A statement that names principals in a policy attached any other way
(one from the policy store, or supplied through `withPolicies()`) is recorded the same way and never allows. The tenant
stage runs first, so a resource of a tenant outside the subject's scope is still denied as `tenant_scope` before any
policy is read: a resource policy never allows across tenants, and the guardrails and the subject's permission
boundaries are weighed before any allow, so they cap a resource policy's allow as they cap every other. When a subject
is admitted to such a resource through a platform-wide permission, and the check runs at platform scope, a deny attached
to the resource in its own tenant still applies: the resource's owner can lock it against everyone, a support user with
a platform-wide grant included. That tenant's resource-policy allows do not reach the subject there. `withPolicies()`
bypasses the resource's policies with the rest; give a supplied policy a resource with `Policy::withResource('post:42')`
to have it evaluated as one.

The decision, the trace and `explain()` name a resource policy's statements as they name any other, with the resource
the policy is attached to: `post-42-sharing[<its key>]#0 sid="reviewers-read" on "post:42"`. `authorization:why`
passes a `post:42` resource to the check as the `['post', '42']` pair, so it reads that record's resource policies and
those of its type, and `post:*` as the type alone; with `--opaque`, the resource is an opaque identifier and reads none.
