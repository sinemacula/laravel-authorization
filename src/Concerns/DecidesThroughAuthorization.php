<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Auth\Access\Response;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\PolicyResponses;

/**
 * Lets a Laravel policy class decide through the package (AUTHZ-9.2).
 *
 * Each policy method names its action explicitly and hands the user Laravel
 * gives it, and its model or any other resource, to `decide()`, which makes
 * exactly one full decision through `Authorization::forUser($user)->check()`:
 * recorded as the last decision and reported as every check is. No method name
 * is mapped to an action: an `update(User $user, Post $post): Response` method
 * returns `$this->decide($user, 'posts:update', $post)`.
 *
 * The decision becomes `Response::allow()`, or `Response::deny()` with the
 * decision's reason code as its code and the generic translated `denied` line
 * as its message, whatever the reason (see `PolicyResponses`); never a
 * not-found response. An `insufficient_authentication` denial keeps its own
 * code, but the trait does not raise the step-up exception or carry the
 * requirements: a caller that needs them uses `authorize()` or `check()`. A
 * guest (a null user) is no subject, so it is denied as `subject_unresolved`.
 *
 * For an ability the package's Gate hook answers, the hook decides before any
 * policy class runs, so the trait serves abilities outside the catalogue's
 * exact names, and applications that switch the hook off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait DecidesThroughAuthorization
{
    /**
     * Decide the action for the user on the resource, as a policy response.
     *
     * @param  object|null  $user
     * @param  string  $action
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     * @return \Illuminate\Auth\Access\Response
     */
    protected function decide(?object $user, string $action, mixed $resource = null, array $context = []): Response
    {
        return PolicyResponses::of(Authorization::forUser($user)->check($action, $resource, $context));
    }
}
