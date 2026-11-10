<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Diagnostics;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Facades\Authorization;

/**
 * A sibling package's provider that boots before the authorization package's,
 * and keeps in the container what it found as it booted: the class the tenant
 * tree resolved to, whether the package had decided how it boots, and what a
 * check asked of the package threw.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EarlyBootingProvider extends ServiceProvider
{
    /** @var string The key the class the tenant tree resolved to is kept under. */
    public const string TENANT_TREE = 'probe.tenant_tree';

    /** @var string The key whether the package had decided how it boots is kept under. */
    public const string DECIDED = 'probe.decided';

    /** @var string The key what a check threw is kept under. */
    public const string CHECK = 'probe.check';

    /**
     * Keep what the provider found as it booted.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->app->instance(self::TENANT_TREE, $this->app->make(TenantTree::class)::class);
        $this->app->instance(self::DECIDED, PackageState::of($this->app)?->isDecided());

        try {
            $this->app->instance(self::CHECK, Authorization::can('posts:read'));
        } catch (InvalidAuthorizationConfigException $refusal) {
            $this->app->instance(self::CHECK, $refusal);
        }
    }
}
