<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use PHPUnit\Framework\Attributes\After;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Support\DeclaredActionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use Tests\Feature\Stubs\ConfigurablePermissionProvider;

/**
 * Declares the permissions a test names through a provider, and binds the
 * declared action catalogue in place of the test suite's permissive one, so
 * only those and the package's own may be created or granted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait DeclaresPermissions
{
    /**
     * Declare the permissions, each guard-agnostic.
     *
     * @param  string  ...$names
     * @return void
     */
    protected function declarePermissions(string ...$names): void
    {
        ConfigurablePermissionProvider::$permissions = \array_map(static fn (string $name): PermissionDefinition => new PermissionDefinition($name), \array_values($names));

        config(['authorization.permission_providers' => [ConfigurablePermissionProvider::class]]);

        $this->app?->instance(ActionCatalogue::class, $this->app->make(DeclaredActionCatalogue::class));
    }

    /**
     * Forget the permissions the test declared.
     *
     * @return void
     */
    #[After]
    protected function forgetDeclaredPermissions(): void
    {
        ConfigurablePermissionProvider::$permissions = [];
    }
}
