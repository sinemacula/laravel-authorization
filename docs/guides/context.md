# Context, attributes and authentication requirements

What a policy's conditions read: the check's namespaced context, the attributes of the subject and the resource, and
the authentication requirements an allow can carry.

## The check's context

A policy's conditions and `${…}` references read the check's context: nested namespaces, each key a dot path within
one. A namespace is built only when a statement under evaluation reads it, through a condition key or a reference, and
at most once a check, so a check whose policies read nothing of the request never looks at it.

| Namespace        | Keys                            | Comes from                                                  |
|------------------|---------------------------------|-------------------------------------------------------------|
| `authentication` | `guard`, `user_id`, `user_type` | The bound `AuthenticationContext`                           |
| `request`        | `ip`, `method`, `route`         | The bound `RequestContext`, only in a routed request        |
| `environment`    | `time`                          | The bound `EnvironmentContext`                              |
| `subject`        | `id`, `type`, `tenant.*`, more  | The check's subject and its attribute provider              |
| `resource`       | `id`, `type`, `tenant.*`, more  | The check's resource and its attribute provider             |
| `input`          | The keys you declare            | What the caller passes                                      |
| Any other        | The keys its owner declares     | A `ContextSource` listed in `authorization.context.sources` |

The shipped defaults supply what Laravel knows. `authentication` holds the default guard's name and, when someone is
signed in on it, the user's key as a string and morph type (the morph alias, or the class name); with nobody signed in
only `guard` is present. `request` holds Laravel's `ip()`, resolved through your trusted proxies, the method and the
route's name, and only once the request has been routed: in a queued job or a console command the namespace is absent,
so every `request` key is missing. `environment.time` is `now()` in UTC as `Y-m-d\TH:i:s\Z`, fixed the first time the
check reads `environment`, then kept for the rest of the check, so `Carbon::setTestNow()` freezes it in tests.
`subject` and `resource` describe who the check is about and what it is on; see [Subject and resource
attributes](#subject-and-resource-attributes).

What the caller passes lands under `input`, and only there: the `$context` of `check()`, `can()`, `cannot()`, `any()`,
`all()`, `authorize()`, `explain()`, `canEach()`, `filterAuthorized()`, each `CheckInput` of `checkMany()`,
`permissionsFor()` and a policy class's `decide()`, the string-keyed and associative arguments of a Gate check,
and the context of `assertCan()` and `assertCannot()`. A caller can never supply a trusted value:

```php
Authorization::can('posts:publish', $post, ['post' => ['status' => 'draft']]); // input.post.status
Gate::allows('posts:publish', [$post, ['post' => ['status' => 'draft']]]);     // input.post.status
Authorization::can('posts:delete', $post, ['request' => ['ip' => '10.0.0.1']]); // input.request.ip, never request.ip
```

Every key a policy reads must be declared in the context key catalogue, with a type, or the policy is refused when it
is saved. The package declares its own keys, those in the table above, and your attribute providers declare theirs;
declare the rest, `input`'s included, in `config/authorization.php`, each path within its namespace:

```php
'context' => [
    'keys' => [
        'input'  => [
            'post.status'      => 'string',
            'post.tenant'      => 'string',
            'post.archived_at' => 'time',
            'groups'           => 'list',
        ],
        'tenant' => ['plan' => 'string', 'seats' => 'number'],
    ],
    'sources' => [App\Authorization\TenantContext::class],
],
```

or register them from a service provider, which is how a package adds its namespace:

```php
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;

public function boot(): void
{
    $keys = $this->app->make(ContextKeyCatalogue::class);

    $keys->register('device', ['trusted' => 'bool', 'platform' => 'string']);
    $keys->declare('device.enrolled_at', ContextKeyType::TIME);
}
```

A key's type decides the operators a condition may test it with; `null` suits every type, and an `_if_exists` form
follows its operator. A key may also be declared untestable (`declare($path, $type, isTestable: false)`), so that a
reference may read it but no condition may test it. The assurance keys of the authentication context are always
untestable, and not even a reference may read them (see [Assurance keys](#assurance-keys)). Declaring a key again
with another type is refused, and so is a key under `subject` or `resource`, whose keys come only from the package and
the attribute providers. The type is checked when the policy is written; a value of the wrong type at evaluation is
still undecidable.

| Type     | Operators                                                       |
|----------|-----------------------------------------------------------------|
| `string` | `eq`, `neq`, `in`, `not_in`, `starts_with`, `ends_with`, `like` |
| `number` | `eq`, `neq`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`           |
| `bool`   | `eq`, `neq`, `bool`                                             |
| `time`   | `before`, `after`, `between`                                    |
| `ip`     | `eq`, `neq`, `in`, `not_in`, `ip_in`, `ip_not_in`               |
| `list`   | `any_value_in`, `all_values_in`                                 |

An application adds a namespace with a class implementing `SineMacula\Laravel\Authorization\Contracts\ContextSource`,
listed in `authorization.context.sources` and resolved from the container. It names its namespace and returns its
values, nested by key; an empty array leaves the namespace absent:

```php
use SineMacula\Laravel\Authorization\Contracts\ContextSource;

final class TenantContext implements ContextSource
{
    public function __construct(private CurrentTenant $tenant) {}

    public function namespace(): string
    {
        return 'tenant';
    }

    public function values(): array
    {
        $tenant = $this->tenant->get();

        return $tenant === null ? [] : ['plan' => $tenant->plan, 'seats' => $tenant->seats];
    }
}
```

A source that does not implement the contract, one that claims a reserved namespace (`authentication`, `request`,
`environment`, `input`, `subject` or `resource`), two sources claiming one namespace, and a source claiming a namespace
your `AuthenticationContext` adds are refused at boot. The trusted namespaces are replaced only by rebinding
their own contracts. To supply `authentication` from your authentication layer, along with any namespace it adds
beside it such as `mfa` or `sso`, bind your own `AuthenticationContext`. Its `namespaces()` lists every namespace it
supplies and `values()` returns their values keyed by namespace; declare the keys of any namespace it adds in the
catalogue. `assuranceKeys()` declares the names that make a key of those namespaces an assurance key (see
[Assurance keys](#assurance-keys)). It is resolved at boot, which refuses a namespace it adds that is not a name, is
reserved or is listed twice, and a malformed assurance key name. Bind it in a service provider's `register()`:

```php
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;

$this->app->scoped(AuthenticationContext::class, App\Authorization\SessionAuthenticationContext::class);
```

`RequestContext` and `EnvironmentContext` are rebound the same way. The defaults are built per request or job, so queue
workers and Octane read the request and the user they are serving; a binding of your own is kept as you bound it.

`namespaces()` and `assuranceKeys()` must answer the same for the life of the process, and should be cheap and free of
side effects, since the package reads them more than once, though never while providers register: at boot, to validate
them; at the context key catalogue's first use, not when the catalogue is built, which keeps what they said from then
on; each time a policy document is validated, on a write or by `authorization:policy:validate`; and, `namespaces()`
alone, each time the check context factory is built, once per request or job. A context bound in any provider's
`register()` is therefore the one read, whichever provider registers first, even when another resolves the catalogue
or declares keys in it while it registers. Register keys from `boot()`, as above, so the catalogue's first use comes
after every provider has registered.

## Subject and resource attributes

The `subject` namespace describes who the check is about and `resource` what it is on. The package declares and
supplies their built-in keys, every one a string:

| Key                                          | Holds                                                                      |
|----------------------------------------------|----------------------------------------------------------------------------|
| `subject.id`                                 | The subject's key (`getKey()` for a model)                                 |
| `subject.type`                               | The subject's morph type (the morph alias, or the class name)              |
| `subject.tenant.type`, `subject.tenant.id`   | The morph type and key of the tenant the subject resolver gave the subject |
| `resource.id`                                | The record's key, for a check on one record                                |
| `resource.type`                              | The resource's type, for a record or a type alone                          |
| `resource.tenant.type`, `resource.tenant.id` | The resource's tenant, from the resource tenant resolver or its reference  |

A check with no subject has no `subject` namespace, and one without a resource has no `resource` namespace; the tenant
keys are missing when there is no tenant. A model, or a `(type, id)` pair, names a record and has both `resource.id`
and `resource.type`. A model class (`Post::class`) names a type alone, so only `resource.type` is present. Any other
string is an opaque identifier with neither: `'reports:42'` is never split at its `:`.

Every other attribute comes from a provider, registered for one morph type. A resource attribute provider implements
`SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider`: `attributes()` declares each attribute, a dot
path within `resource`, with its type, and `values()` returns a record's values, nested by key. It is given the
record's reference and the model the check was given, so it can read the model rather than query for it. A model that
implements `AuthorizableResource` is handed on too, when the reference it returns names one record and carries no
model. The model is null when the check named the record some other way, such as a `(type, id)` pair or an
`AuthorizableResource` that is not a model:

```php
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

final class PostAttributes implements ResourceAttributeProvider
{
    public function attributes(): array
    {
        return ['status' => 'string', 'owner.id' => 'string'];
    }

    public function values(ResourceReference $resource, ?Model $model): array
    {
        $post = $model ?? Post::query()->find($resource->id);

        return $post === null ? [] : ['status' => $post->status, 'owner' => ['id' => (string) $post->user_id]];
    }
}
```

A subject attribute provider implements `SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider` the same
way, its `values()` given the subject:

```php
use SineMacula\Laravel\Authorization\Contracts\SubjectAttributeProvider;

final class UserAttributes implements SubjectAttributeProvider
{
    public function attributes(): array
    {
        return ['department' => 'string', 'clearance' => 'number'];
    }

    public function values(object $subject): array
    {
        return ['department' => $subject->department, 'clearance' => $subject->clearance_level];
    }
}
```

Register each under the morph type it serves (the morph alias, or the class name) in `config/authorization.php`. They
are resolved from the container:

```php
'attributes' => [
    'resources' => ['post' => App\Authorization\PostAttributes::class],
    'subjects'  => ['user' => App\Authorization\UserAttributes::class],
],
```

A policy then reads them like any other key, through a condition or a `${…}` reference:

```php
'conditions' => [
    'eq' => ['resource.owner.id' => '${subject.id}'],
    'in' => ['resource.status' => ['draft', 'review']],
],
```

What a provider declares enters the key catalogue at boot. A class that does not implement its contract or cannot be
resolved, a provider declaring a built-in (`id`, `type` or anything under `tenant`), a provider declaring a key under
another key it declares (`owner` and `owner.id`), and two providers declaring one key with different types are refused
at boot; two providers may declare one key alike. Only the keys a provider declares are exposed: a value it returns
for any other key is dropped, and so is everything under a declared key. A declared key holds a scalar or `null`, or,
for a `list`, a list of them; a map, or a list under any other type, stays present but cannot be read into, so a test
of the key is undecidable, `${…}` does not resolve it and none of the keys under it can be read. A value of the wrong
type is undecidable when the policy is evaluated, as for any context value.

A namespace is built the first time a statement under evaluation reads any of its keys, built-in or not, and at most
once a check, so a provider is asked at most once a check, and not at all by a check whose policies read nothing of
its namespace. Nothing is kept for the next check. The resource provider is asked only about a record: a type alone,
an opaque identifier, no resource and a type with no provider leave only the built-ins that apply, so an attribute key
is missing. A missing key makes its test undecidable, so an allow on it does not apply and a deny does, unless it is
tested with `null` or an `_if_exists` operator.

A provider that throws aborts the check rather than letting it be decided with the attribute missing: `check()`,
`can()`, `authorize()`, the Gate and every other entry point throw
`SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed`, with the provider's exception as its previous
one. No decision is made, so no decision event is dispatched and the check records no last decision. The message names
the provider's class and the namespace, never an attribute value, and nothing the provider returned or threw reaches a
decision, an event or the trace.

## Authentication requirements

An allow can require that the subject's session was authenticated strongly enough, and recently enough, for the
action. State it with the `authentication_requirement` operator on the reserved key `authentication`:

```php
[
    'sid'        => 'refund-after-step-up',
    'effect'     => 'allow',
    'actions'    => ['invoices:refund'],
    'conditions' => [
        'authentication_requirement' => [
            'authentication' => [
                'multifactor'        => ['max_age' => 900],
                'phishing_resistant' => [],
            ],
        ],
        'eq' => ['resource.tenant.id' => '${subject.tenant.id}'],
    ],
],
```

The operand maps one or more parts to their options, `{}` (an empty array) for none:

| Part                      | Requires                                                    | Options                         |
|---------------------------|-------------------------------------------------------------|---------------------------------|
| `additional_verification` | A verification beyond the sign-in, such as a password again | `max_age`                       |
| `multifactor`             | Multifactor authentication                                  | `max_age`                       |
| `phishing_resistant`      | A phishing-resistant proof, such as a passkey               | `max_age`                       |
| `assurance_level`         | An assurance level of at least `min`                        | `min` (required), and `max_age` |

`max_age` is a whole number of seconds, at least 1: the proof that meets the part must be no older. `min` is a string
that is not empty or blank, an assurance level your checker knows, and no longer than the `pattern_length` limit. Every
part named must be met, and the requirement is one test judged whole, so it counts as one key test against the
`conditions` limit. The policy is refused when it is saved if the requirement is on any key but `authentication`, names
no part, an unknown part or an unknown option, gives a `max_age` that is not a whole number of at least 1, or gives
`assurance_level` no `min`. There is no `authentication_requirement_if_exists`. `authentication` is not read from the
context here, so the requirement needs no key declared in the catalogue.

### The requirement checker

A requirement is judged by the bound
`SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker`, given the requirement and the check's
`Subject`. The checker fetches the proofs of the subject's `session` itself, so the newest proof that meets each part
is judged, never separate scalar tests that a fresh weak proof and a stale strong one could meet together; the package
never passes proofs or `amr` in. It answers with a `RequirementResult`: met, with the instant until which the
requirement stays met when it knows one, or unmet, with the parts that are not met:

```php
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Subject;

final class SessionProofChecker implements AuthenticationRequirementChecker
{
    public function __construct(private SessionProofs $proofs) {}

    public function check(AuthenticationRequirement $requirement, Subject $subject): RequirementResult
    {
        $proofs = $this->proofs->of($subject->session);
        $unmet  = array_values(array_filter(
            $requirement->names(),
            fn (string $part): bool => !$proofs->meets($part, $requirement->maxAge($part), $requirement->minimumLevel),
        ));

        return $unmet === []
            ? RequirementResult::met($proofs->metUntil($requirement))
            : RequirementResult::unmet($unmet);
    }
}
```

Name it in `config/authorization.php`, where it is checked at boot and built per request or job, or bind the contract
yourself:

```php
'requirement_checker' => App\Authorization\SessionProofChecker::class,
```

The default, `RefusingRequirementChecker`, finds every part of every requirement unmet, so until you bind a checker an
allow that states a requirement never applies. The checker is asked afresh for every requirement of every check, and
nothing it answers is remembered. A met result whose instant has already passed counts as unmet, every part with it. An
unmet result keeps only the parts the requirement names, and one that names none of them leaves every part unmet. A
checker that throws makes the test undecidable, so an allow it guards does not apply and a deny it guards does; the
failure is logged at debug level by the checker's class and the exception's class alone, never with the exception's
message or anything the checker held.

### Sessions

`Subject::$session` is the session the checker judges. The shipped resolver sets it to the current request's session
id only when that session signed in that very user: the guard is a `SessionGuard` using the request's session, and the
session's login key names the user, compared strictly as strings. That holds for the user signed in on its guard,
including when the Gate hands it that same user. It is null for a user set on the guard without the session
(`Auth::once()`, `onceUsingId()`, `onceBasic()`, the `auth.basic.once` middleware or `setUser()`), whatever login the
session holds; for a user a token or request guard returns; for a subject you name (`Authorization::for($user)`, or
`Gate::forUser()` with another user); and outside a session (a console command, a queued job, a request without a
started session). A subject without a session meets no requirement: every part is unmet and the checker is not asked.
A resolver of your own sets `session` to whatever its checker knows the proofs by, and only for the user that session
authenticated. Your checker should still confirm the proofs it finds belong to `$subject->subject`.

### The decision and the exception

A check is denied as `insufficient_authentication` when no deny applies, no invalid policy blocks it, every permission
boundary allows it, nothing else allows it (no other allow statement and no permission held), and at least one allow
statement names the action and the resource with every other condition holding and only its requirement unmet. It ranks
above `condition_failed`, and deny precedence always wins. A requirement that cannot be checked is undecidable, not
unmet, so its statement is no candidate and, alone, leaves the check `condition_failed`. The decision's `requirements`
lists each such statement's requirement with its unmet parts, as an `UnmetRequirement`: they are alternatives, any one
of which met would allow the check. On a deny statement an unmet requirement is a test that does not hold, so the deny
does not apply, while one that cannot be checked applies it, as any undecidable test does. The trace records the
requirement as the key `authentication`, with whether it held, and never a proof.

`authorize()`, and the `permission:` and `authorize:` middleware, throw
`SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException` for it. It extends Laravel's
`Illuminate\Auth\Access\AuthorizationException`, not the package's, so a handler that maps the package's denials does
not catch it, and an application that maps it to nothing still answers `403`. It carries the reason code (`getReason()`)
and the candidate requirements, once each (`requirements()`); never a policy, a statement, the trace or a proof. Its
message is the generic `authorization::authorization.denied` line, as every denial's is, so a step-up prompt is the
application's own to word (see [Localisation](localisation.md#localisation)). Like any denial, it is recorded as the
last decision and fires `AuthorizationFailed` first. Map it to your step-up response, such as RFC 9470's
`insufficient_user_authentication` challenge:

```php
// bootstrap/app.php
use Illuminate\Foundation\Configuration\Exceptions;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;

->withExceptions(function (Exceptions $exceptions): void {
    $exceptions->render(fn (InsufficientAuthenticationException $exception) => response()->json(
        [
            'message'      => __('Confirm your identity to continue.'),
            'requirements' => array_map(
                fn (UnmetRequirement $candidate): array => $candidate->toArray(),
                $exception->requirements(),
            ),
        ],
        401,
        ['WWW-Authenticate' => 'Bearer error="insufficient_user_authentication"'],
    ));
})
```

A decision that read a requirement is reused only while it still holds. `Authorization::lastDecision()` returns it only
in the session of the request that recorded it, whichever subject it was about (one named with `for()` included), and
until the earliest instant a met requirement it read stops being met. The decision's own `$decision->freshness` keeps a
fingerprint of the session it was made in (its SHA-256 hash, never the session id, so the decision stays safe to log)
and that instant, and `isFreshFor($session)` says whether it may be reused in a session. Nothing else keeps a decision:
`can()`, `cannot()`, `any()`, `all()`, `checkMany()`, `canEach()`, `filterAuthorized()`, the Gate, a policy class's
`decide()`, the Blade directives and `permissionsFor()` decide afresh every time, and the resolution cache holds
grants and policies, never decisions.

### Forgetting decisions

The last decision, and what the resolution cache, the tenant scope and a running batch of checks hold for the request
or job, outlive a change to the proofs or the session they were read under. A suite package or the application calls
`Authorization::forgetDecisionsFor($session, $identity)` once a proof is recorded or revoked (a step-up met, a factor
removed), a session signs in or out, or the tenant is switched inside the request or job, and the rest of it decides
afresh:

```php
// A step-up was just recorded for the signed-in session.
Authorization::forgetDecisionsFor($request->session()->getId(), $request->user());

Authorization::lastDecision();          // null
Authorization::can('reports:export');   // decided afresh, the new proof read
```

It clears the last decision, its provenance and the session it was recorded in, empties the resolution cache's
in-memory tier, in every scope, without touching the persistent store or bumping a version key (no grant changed, so
other workers keep what they hold), and drops the tenant and application resolved for the request, so the next check
reads the subject, its session and its tenant from the subject resolver again. A scope put in place with
`TenantScope::within()` or an `AuthorizationScope` stays as you set it until it ends, and a manager from `for()` or
`forUser()` keeps its subject and decides afresh about it, a `Subject` given to `for()` in its own tenant even when that
is the request's. A batch of checks still running reads ahead again from its next chunk: a batch about the request's
subject asks the subject resolver for it again, with its session, its credential's scopes and its tenant, so the checks
still to come, and `lastDecision()` after them, follow the change. A preview admits its previewer again at its next
decision. The session caps are read from the session policy source at every check, so there is nothing of them to
forget.

The session and the identity name what changed, for the reader of your code: in this version everything is forgotten,
for every session and every identity, whatever they are, null included. A decision already returned and an event
already dispatched are observations of what was decided then, and are never retracted. Forgetting is not a decision, so
a manager never refuses it, even while the package refuses its configuration. `forgetLastDecision()` clears the last
decision alone, as a long-running worker does between requests.

### Under the suite

With `sinemacula/laravel-iam`, the checker is bound to `laravel-mfa`'s requirement check, and the `mfa` namespace comes
through the authentication context. `laravel-iam` maps `InsufficientAuthenticationException` to MFA's step-up
exception, which owns the RFC 9470 response and the mapping from assurance levels to `acr` values, so only one package
produces step-up responses and the application maps nothing itself. This package never reads MFA's tables or a
session's proofs, never treats `mfa` in `amr` as multifactor authentication, and never decides who must use MFA.

### Assurance keys

An assurance level, the time of authentication or the seconds since a step-up can sit in the context for your own code
to show or log, but a policy may not decide on them: separate scalar tests could be met by a fresh weak proof and a
stale strong one together, which the requirement checker never allows. A key of `authentication`, or of a namespace
your `AuthenticationContext` adds beside it (such as `mfa`), is an assurance key when any segment of its path after the
namespace is `assurance_level`, `auth_time`, `seconds_since_step_up`, `last_verified_at`, `verification_age`,
`multifactor` or `amr`, so `authentication.amr` and `mfa.multifactor.enabled` both are. The package declares none of
them, and whatever the declaring context or configuration says, the catalogue declares each one untestable. A policy
with a condition on one, or a `${…}` reference to one in an operand or a resource pattern, is refused when it is
saved, and when `authorization:policy:validate` reads it, with a reason that points at `authentication_requirement`.

Your `AuthenticationContext` declares its own assurance key names in `assuranceKeys()`, beside these fixed ones, which
it can never remove. Each is either an exact name, or a name followed by one trailing `*`, which matches every segment
starting with what comes before it; nothing else is accepted. A name that is not a string, is empty, holds a `.` or
has a `*` anywhere but at its end is refused at boot, and a policy write fails closed on it. A sibling package that
supplies verification proofs and the identity providers a session came through might declare:

```php
public function namespaces(): array
{
    return ['authentication', 'verification', 'federation'];
}

public function assuranceKeys(): array
{
    return ['recovery_code', 'level', 'factor_types', 'last_verification_age_seconds', 'provider_*'];
}
```

`verification.level`, `verification.factors.recovery_code` and `federation.provider_name` are then assurance keys,
and no condition may test them; `verification.enrolled` is not. The shipped `GuardAuthenticationContext` declares none.
