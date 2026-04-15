<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Facades;

use Illuminate\Support\Facades\Facade;
use SineMacula\Laravel\Authorization\AuthorizationManager;

/**
 * Authorization facade.
 *
 * Static proxy to the container-bound authorization manager. Every
 * call is forwarded to a fresh manager scope so `for()` /
 * `withPolicies()` chains do not leak between requests.
 *
 * @method static bool can(string $action, string|null $resource = null, array<string, mixed> $context = [])
 * @method static void authorize(string $action, string|null $resource = null, array<string, mixed> $context = [])
 * @method static \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult evaluate(string $action, string|null $resource = null, array<string, mixed> $context = [])
 * @method static \SineMacula\Laravel\Authorization\AuthorizationManager for(object $principal)
 * @method static \SineMacula\Laravel\Authorization\AuthorizationManager withPolicies(array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy> $policies)
 * @method static \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult|null lastDecision()
 * @method static void forgetLastDecision()
 * @method static string explain(string $action, string|null $resource = null, array<string, mixed> $context = [])
 *
 * @see AuthorizationManager
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class Authorization extends Facade
{
    /**
     * Return the container-binding key for the facade accessor.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'authorization';
    }
}
