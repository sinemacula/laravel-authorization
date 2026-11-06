<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * Authorization facade.
 *
 * Static proxy to the container-bound authorization manager. The facade
 * resolves the manager scoped to the current request or job, so every call in
 * that lifecycle reaches the same manager and a new one is made for the next.
 * `for()`, `forUser()`, `withPolicies()` and `capped()` never change it: each
 * returns a new scoped clone, which shares the lifecycle's last-decision store,
 * so `lastDecision()` reads the latest decision of any of them.
 *
 * @phpcs:disable Generic.Files.LineLength.TooLong
 *
 * @method static bool can(string $action, mixed $resource = null, array<string, mixed> $context = [])
 * @method static bool cannot(string $action, mixed $resource = null, array<string, mixed> $context = [])
 * @method static bool any(array<int, string> $actions, mixed $resource = null, array<string, mixed> $context = [])
 * @method static bool all(array<int, string> $actions, mixed $resource = null, array<string, mixed> $context = [])
 * @method static void authorize(string $action, mixed $resource = null, array<string, mixed> $context = [])
 * @method static \SineMacula\Laravel\Authorization\Evaluation\Decision check(string $action, mixed $resource = null, array<string, mixed> $context = [])
 * @method static \SineMacula\Laravel\Authorization\AuthorizationManager for(object $subject)
 * @method static \SineMacula\Laravel\Authorization\AuthorizationManager forUser(object|null $user)
 * @method static \SineMacula\Laravel\Authorization\AuthorizationManager withPolicies(array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy> $policies)
 * @method static \SineMacula\Laravel\Authorization\AuthorizationManager capped(list<string> $actions)
 * @method static \SineMacula\Laravel\Authorization\Evaluation\Decision|null lastDecision()
 * @method static void forgetLastDecision()
 * @method static string explain(string $action, mixed $resource = null, array<string, mixed> $context = [])
 * @method static array<string, bool> effectivePermissions(array<string, mixed> $context = [])
 * @method static \SineMacula\Laravel\Authorization\Subject|null currentSubject()
 * @method static void treeChanged(\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|\SineMacula\Laravel\Authorization\Support\Reference $tenant)
 *
 * @phpcs:enable Generic.Files.LineLength.TooLong
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @see AuthorizationManager
 */
final class Authorization extends Facade
{
    /**
     * Return the container-binding key for the facade accessor.
     *
     * @return string
     */
    #[\Override]
    protected static function getFacadeAccessor(): string
    {
        return 'authorization';
    }
}
