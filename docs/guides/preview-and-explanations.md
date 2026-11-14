# Preview and explanations

Answering what another subject may do without acting as them, and explaining why a check was allowed or denied.

## Preview

`previewFor()` answers "what can this person do?" for a support or administration screen: it returns a manager whose
checks are about another subject, while the caller stays who is asking. The package never impersonates: the guard, the
session, the Gate, Blade and the facade stay the caller's.

```php
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;

$preview = Authorization::previewFor($user);                            // the request's tenant and application
$preview = Authorization::previewFor($user, AuthorizationScope::tenant($account, 'admin'));

$preview->can('posts:update', $post);
$preview->checkMany($checks);
$preview->explain('posts:delete', $post);
$preview->permissionsFor(null, AuthorizationScope::tenant($account, 'admin')); // null: the previewed subject

Post::query()->whereAuthorized('posts:view', [], $preview)->select(['id', 'title'])->paginate();
```

**Admission and the right.** A preview is itself an action checked here: the caller must be allowed
`authorization:subject.preview`, a permission the package declares, spelt as its administration actions are. It is
decided through `check()` as the caller, with the caller's own session, denies, boundaries, guardrails and caps, on a
preview resource, `authorization:preview:{type}:{id}`, that names the subject and the scope a decision is made in.
Policies read these keys of it, so an application restricts who may be previewed, and where, by policy; no rank rule is
imposed, so an auditor may inspect senior staff on purpose:

| Key                                              | Value                                                                   |
|--------------------------------------------------|-------------------------------------------------------------------------|
| `resource.id`, `resource.type`                   | The principal previewed as `{type}:{id}`, and `authorization:preview`   |
| `resource.tenant.type`, `resource.tenant.id`     | The tenant the decision is made in; missing at platform scope           |
| `resource.target_type`, `resource.target_id`     | The principal previewed, by morph type and key                          |
| `resource.identity_type`, `resource.identity_id` | The identity behind it; missing when it has none that is a saved record |
| `resource.application`                           | The application the decision is made in; missing for none               |

```json
{"statements": [
    {"effect": "allow", "actions": ["authorization:subject.preview"]},
    {
        "effect": "deny",
        "actions": ["authorization:subject.preview"],
        "conditions": {"eq": {"resource.target_type": "admin"}}
    }
]}
```

A missing key makes a deny on it undecidable, so it refuses there, as policies fail closed; use an `_if_exists` operator
to let it pass.

**Admission in every scope a decision is made in.** A decision about the subject is made where any check on its resource
is made: in the preview's tenant, in a resource's own tenant when that is the preview's tenant or below it, a child
tenant's included, just below a tenant for a query's rows below it, and at platform scope for a resource of another
tenant that a platform-wide grant admits. Before any decision about the subject is made in such a scope, the caller is
decided the right there, as an ordinary check: on the preview resource of that tenant, or none at platform scope, with
that tenant and application in place. So a parent's right that reaches its subtree admits a preview in a child, a right
held at a parent's node alone admits no answer below it, and a deny of the right in a child tenant refuses every answer
made there; a resource of another tenant needs a platform-wide grant of the right, since it is answered at platform
scope; and a preview for no application needs the right for every application. A platform preview is decided, and
admitted, at platform scope, where a deny the caller holds in one tenant does not apply, as for any check at platform
scope. A preview distributes no authority, so nothing beyond the ordinary check is weighed: a deny, conditional or not,
refuses only the previews and the scopes it matches.

Each scope is admitted once in each use, so a batch over many resources of one tenant costs one admission for the
preview's tenant and one more for each other scope its decisions are made in, never one per resource. A query through
the preview is cut wherever the caller's sources might differ too, so each of its classes of rows is admitted where it
is decided; it is refused when the caller may not preview in one of them, whether that class holds rows or not.

**Revalidation.** The preview is admitted when it is built and again at every use: each check, each batch, each listing
and each compile of a query scoped through it. Nothing is cached between uses, so a right revoked after the preview
or a query is built refuses the next use. A refused admission throws `AuthorizationException`, with the one `denied`
line and the caller's own decision, before anything about the subject is decided in that scope, so it reveals nothing
about the subject there; in a batch, a listing or a query, it refuses the whole call, which returns nothing, though the
decisions already made in it are reported as any decision is. It is recorded and reported as any check about the
caller. A use sets the request's resolution memo aside and restores it afterwards, so the caller's own checks read
nothing again after a preview.

**The subject has no session.** A resolved `Subject` keeps its principal and identity but not its session, and a model
is named as `for()` names it, so no authentication requirement made of the subject is met, whatever the caller has
proved; the caller's step-up counts for the admission alone. A preview's `authorize()` therefore never throws
`InsufficientAuthenticationException`: a denial for a requirement made of the subject throws a plain
`AuthorizationException`, carrying the decision, since no step-up by the caller could meet it. The subject is evaluated
in the caller's request context: the `request`, `environment` and `authentication` namespaces are the caller's
request's, which is no prediction of what the subject would see when signed in. A resolved `Subject` keeps what its
credential carries, so it still caps the preview: when the `Subject` says nothing of its scopes but names a credential,
a session or a guard whose caller is its own model, the session policy source is asked before the session is dropped and
its answer is kept as said, so a credential the source cannot establish allows nothing. It keeps its platform marker
too: previewed with no scope given, a `Subject` given on the platform is previewed on the platform, on its application,
rather than in the request's tenant, while a model is previewed in the request's scope, whatever marker the request's
subject carries.

**What is recorded.** Every decision about the subject dispatches `DecisionEvaluated` while `events.decisions.previews`
is on, as it is by default, reported as `PREVIEW` whatever `allows` sets, and every `authorize()` refusal dispatches
`AuthorizationFailed`, with `subject` the previewed subject and `previewer` the caller, in the scope the decision was
made in, or the preview's when a listener has meanwhile recorded another decision. A preview `check()` or `checkMany()`
stores the last decision with that provenance. A preview `permissionsFor()` dispatches one event for each action it
evaluates, but stores none of them, so the last decision stays its admission. The admission is a check about the caller,
recorded and reported as any check is, with no previewer, so as an allow it is not reported by default. `explain()` and
a decision's trace are disclosed under the right to preview; they name statements, conditions, caps and requirements,
never a value or a session.

**What is refused.** On a preview, `for()`, `forUser()`, `previewFor()` and `permissionsFor()` naming a subject would
change the target, a listing in another tenant or application would change the scope, and `withPolicies()` would decide
through hypothetical policies: each throws `InvalidPreviewException` before anything is decided, and so does
`previewFor()` on a manager carrying a policy override. `capped()` is allowed and caps the subject's checks alone,
never the caller's admission. A preview never becomes authority to act: an `ActingContext` built while a preview is
evaluated, or from a preview's subject, and every management service call made while a preview is evaluated, from a
callback or a listener, a listener of a preview's `AuthorizationFailed` included, trusted or delegated, is refused with
`AuthorizationException` as `administration.previewing`. There is no override.

**Queries.** `whereAuthorized()` given a preview keeps the rows the previewed subject may take the action on, and its
own writes are refused: an `update()`, a `delete()` or an `insertUsing()` compiled from the preview's own builder, or
from a builder that nests it whole (`whereExists()`, a nested `where()`), is refused as `preview_write`. A preview query
taken into another as SQL text is not (see the limits).

**The disclosure point.** Rows the subject may see are not automatically rows the caller may read. A preview answers
what the subject could do; the application decides what of it to show, with a check of its own about the caller, or by
showing constrained metadata, as the `select()` above does.

**The limits.** A manager clone cannot sandbox everything. A raw Eloquent write on the package's models, pivots or
tables, and a trusted actorless service the application calls outside the preview's evaluation, stay the trusted
integration surfaces they always are. A preview query taken into another as SQL text (`whereIn()`, `fromSub()`,
`joinSub()`, `selectSub()`, `withCount()` or `has()` with a count) is compiled, and admitted, once, when it is taken in;
it is not admitted again when the outer query runs, and it is not refused as `preview_write` when the outer query
writes, so `Post::query()->whereIn('id', $previewQuery->select('id'))->delete()` deletes the rows the subject may see.
Take a preview query in whole, or not into a write at all. See [Preview](../design/preview.md) for the design.

## Explanations

`explain()` answers "why can" and "why can't" (AUTHZ-11.5). It decides the check exactly as `check()` does, through the
same path and the same stages, so its verdict is the same, and records and reports it as any check: it is the last
decision, and its `DecisionEvaluated` is dispatched when `events.decisions` reports it (see [Which decisions are
reported](events.md#which-decisions-are-reported)). It returns an `Explanation`:

```php
$explanation = Authorization::for($user)->explain('posts:publish', $post, ['reason' => 'launch']);

$explanation->isAllowed();
echo $explanation->toText();
return response()->json($explanation); // the versioned schema
```

```text
ALLOW at the allow stage by permission "posts:publish".
  [deny] house-rules[01j...]#0: not_applicable
  [guardrail] guardrails: uncapped
  [boundary] boundaries: uncapped
  [session] session caps: uncapped
  [allow] permission "posts:publish": held
  grant role permission "posts:publish" to principal user:1 through role "editor" < "author" in tenant team:7
  request "posts:publish" on "post:42" about user:1; asked in tenant team:7, decided in tenant team:7
```

**Explain mode and its cost.** `explain()` runs the check in explain mode, a switch on the one decision path (N89). An
everyday check (`check()`, `can()`, the Gate, Blade, the middleware, `checkMany()` and the rest) never turns it on: it
records the trace it always has and costs what it did before explanations. Explain mode decides from what an everyday
check decides from, the resolution cache included, and records more besides, asking no attribute provider more than
the check does. Where each grant came from is read afresh from the grant rows a resolution reads: on a cold cache the
check decides from those rows, in no more queries than an everyday check, and keeps nothing in the cache; on a warm
cache, where an everyday check reads no grant row, an explained check still reads them, once a permission is found held
or the grantee has a policy, in no more queries than a resolution of the names. A grant that the rows no longer give,
one a stale cache still holds, is `unavailable`, never guessed. A preview's `explain()` is admitted, recorded and
reported as any preview check (see [Preview](#preview)).

**What an explanation holds.** It is an immutable value of the decision alone:

- the verdict, the reason and the stage that decided it;
- the statements that decided it, every one when several did, or the cause that is no statement: the guardrail,
  boundary, session cap or administration constraint that refused it, the permission held that allowed it, or the
  reason of an early refusal, such as a check without a subject, whose trace is empty;
- the steps of every stage the decision reached, in order, each statement's condition keys with whether each held and
  the `${…}` references it names, which `keys()` and the events now count too;
- the stages it never reached, marked as not evaluated: after an explicit deny, the caps, the allows and the rest are
  never weighed, nor guessed at;
- each authentication requirement that alone kept an allow from applying, by its part names and its unmet parts;
- for an explained check, each condition test on its own (its key, its operator, whether `_if_exists` lets a missing
  key pass, and its outcome: `held`, `failed`, `missing`, `null`, `wrong_type`, `unresolved`, `undecidable` or
  `invalid`), the keys found missing and every reference that could not be resolved, by key, on the statement that
  read it;
- for an explained allow, where each grant came from: a permission granted to the principal or the identity, or through
  a role, with the role held and each ancestor up to the role that carries it, and the tenant and application of the
  grant; a policy attached to the grantee or to one of its roles, the same way; or a policy attached to the resource, by
  its resource; a role held through a break-glass activation is named `break_glass_permission` or `break_glass_policy`,
  with the activation's key under `activation`, never its note. A source that cannot say, a grantee whose
  `getPermissions()` or `getPolicies()` is its own, a policy store or a policy resolver bound in place of the default,
  is `unavailable`, never guessed;
- for an explained check, what it asked: the action, the resource, the subject, its identity and any previewer, the
  scope it was asked in and the scope it was decided in.

**The renderers.** `toText()` writes it for reading, every name (policy, statement, key, role, tenant) escaped as a JSON
string is (`<`, `>`, `&` and non-ASCII characters as `\uXXXX`, a control character as its JSON escape, such as `\n` or
`\u0001`), so no name can inject markup or a line of its own.
`toArray()`, which `jsonSerialize()` returns, writes a stable schema carrying `version: 1`. Rendering reads the
explanation alone: it queries nothing, dispatches nothing and leaves the last decision as it is.

**What is never shown.** No value: no context or attribute value, operand, interpolated string, model, raw context,
session, proof or fingerprint, in the text, the schema or the value itself (AUTHZ-8.8). What it shows still discloses
how the policies are built, the names of policies, statements, keys, roles and tenants, so show it to those allowed to
see them; another subject's explanation goes through a preview, whose right discloses it.

**A stored decision.** `Decision::explain()` explains any decision, the last decision of an everyday check included,
with the evidence it has: the verdict, what decided it, the steps of its trace, the stages it never reached and its
requirements. What only explain mode records, the condition tests, the keys found missing, the grants' provenance and
the request, is marked `not recorded (explain mode off)`; nothing is evaluated again to fill it in.

**From the command line.** `authorization:why` explains a saved subject's check under the scope and console context its
options name, without the subject's browser session (see
[Explaining a check from the console](console.md#explaining-a-check-from-the-console)). See
[Explanations](../design/explanations.md) for the design.
