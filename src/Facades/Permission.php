<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * Permission facade.
 *
 * Provides static access to the permission manager for convenient
 * authorization checks throughout the application.
 *
 * @method static bool can(string $action, ?string $resource = null, array<string, mixed> $context = [])
 * @method static void authorize(string $action, ?string $resource = null, array<string, mixed> $context = [])
 * @method static \SineMacula\Laravel\Iam\Permissions\Evaluation\EvaluationResult evaluate(string $action, ?string $resource = null, array<string, mixed> $context = [])
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @see         \SineMacula\Laravel\Iam\Permissions\PermissionManager
 */
class Permission extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'iam.permissions';
    }
}
