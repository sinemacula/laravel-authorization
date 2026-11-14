# Localisation

Every message the package can put in front of a client is a translation key of its `authorization` language file.
There are two:

| Key                                            | English                        | Carried by                                                                                                                                                                                     |
|------------------------------------------------|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `authorization::authorization.denied`          | `This action is unauthorized.` | Every denial: `AuthorizationException` and `InsufficientAuthenticationException`, from `authorize()` and the route middleware, and a `DecidesThroughAuthorization` policy's `Response::deny()` |
| `authorization::authorization.unauthenticated` | `Unauthenticated.`             | The `AuthenticationException` the route middleware throw for a request without a subject                                                                                                       |

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
policy response, and render a line of your own for it. Laravel's handler turns an `AuthorizationException` into an
`AccessDeniedHttpException` before it runs a render callback, so the callback takes that and reads the package's
exception as its previous one. A step-up prompt reads an `InsufficientAuthenticationException` the same way (see
[Authentication requirements](context.md#authentication-requirements)):

```php
// bootstrap/app.php
use Illuminate\Foundation\Configuration\Exceptions;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

->withExceptions(function (Exceptions $exceptions): void {
    $exceptions->render(function (AccessDeniedHttpException $exception) {
        $denial = $exception->getPrevious();

        if (! $denial instanceof AuthorizationException) {
            return null;
        }

        return response()->json(
            ['message' => __("denials.{$denial->getReason()->value}"), 'code' => $denial->getReason()->value],
            403,
        );
    });
})
```

```php
$response = Gate::inspect('archive', $post);
$message  = $response->allowed() ? null : __("denials.{$response->code()}");
```

A policy response carries a code only from a policy using `DecidesThroughAuthorization`: an ability the package's Gate
hook answers, such as `posts:archive`, is answered with a bare boolean, so its `Gate::inspect()` response has none. The
reason codes are those of `DecisionReason`, listed under [How a check is decided](policies.md#how-a-check-is-decided).

The two lines cover the denials and the unauthenticated response, the messages a client sees. The package's other
messages are diagnostics for developers and administrators, and stay untranslated: the validators' refusals of a
policy document, a name or a mistaken route or directive argument (`InvalidCheckArgumentException`), a management
service's refusal (a protected system record, an unknown role or permission, a mismatched guard or tenant), the
configuration validator's errors, a `QueryScopeRefusedException`, and the console commands' output.
