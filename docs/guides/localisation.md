# Localisation

Every message the package can put in front of a client is a translation key of its `authorization` language file
(AUTHZ-9.7). There are two:

| Key                                            | English                        | Carried by                                                                                                                                                             |
|------------------------------------------------|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `authorization::authorization.denied`          | `This action is unauthorized.` | Every denial: `AuthorizationException` and `InsufficientAuthenticationException`, from `authorize()` and the route middleware, and a policy class's `Response::deny()` |
| `authorization::authorization.unauthenticated` | `Unauthenticated.`             | The `AuthenticationException` the route middleware throw for a request without a subject                                                                               |

Every denial carries the one generic `denied` line, whatever its reason: an explicit deny, a missing role,
`insufficient_authentication` and every other. Laravel's handler renders the message and not the reason code, so by
default a client learns that it was refused and not why; what more to tell it is the application's choice. Each line
is translated in the current locale when the exception or response is built. Without a translator, or when the locale
has no line for the key, the message is Laravel's own English (`This action is unauthorized.`, `Unauthenticated.`).
Laravel's exception handler is left as it is, and renders the message as it renders any `403` or `401`.

To reword a line, or to add a locale, publish the package's language files into `lang/vendor/authorization`:

```bash
php artisan vendor:publish --tag=authorization-lang
```

Then edit `lang/vendor/authorization/en/authorization.php`, or add a file for another locale beside it, such as
`lang/vendor/authorization/fr/authorization.php`. Laravel reads a published line in place of the package's, so a file
needs only the keys it changes:

```php
// lang/vendor/authorization/fr/authorization.php
return [
    'denied'          => 'Cette action n’est pas autorisée.',
    'unauthenticated' => 'Non authentifié.',
];
```

To word a message per reason, read the reason code the denial carries, `getReason()` on the exceptions and `code()` on a
policy response, and render a line of your own for it. A step-up prompt is worded the same way, in the
`InsufficientAuthenticationException` mapping shown under [Authentication
requirements](context.md#authentication-requirements):

```php
// bootstrap/app.php
use Illuminate\Foundation\Configuration\Exceptions;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;

->withExceptions(function (Exceptions $exceptions): void {
    $exceptions->render(fn (AuthorizationException $exception) => response()->json(
        ['message' => __("denials.{$exception->getReason()->value}"), 'code' => $exception->getReason()->value],
        403,
    ));
})
```

```php
$response = Gate::inspect('archive', $post);
$message  = $response->allowed() ? null : __("denials.{$response->code()}");
```

The reason codes are those of `DecisionReason`, listed under [How a check is
decided](policies.md#how-a-check-is-decided).

AUTHZ-9.7 covers the denials and the unauthenticated response, the messages a client sees. The package's other
messages are diagnostics for developers and administrators, and stay untranslated: the validators' refusals of a
policy document, a name or a mistaken route or directive argument (`InvalidCheckArgumentException`), a management
service's refusal (a protected system record, an unknown role or permission, a mismatched guard or tenant), the
configuration validator's errors, and the console commands' output.
