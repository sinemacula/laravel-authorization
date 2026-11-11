<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Support\RequestState;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\TestCase;

/**
 * Tests for forgetting the package's per-request state in a booted application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestState::class)]
final class RequestStateTest extends TestCase
{
    /**
     * The manager and the per-request state the package bound are built afresh
     * after forgetting, while its state after boot and Laravel's own scoped
     * state are kept.
     *
     * @return void
     */
    public function testThePackagesPerRequestStateIsBuiltAfreshAndTheRestKept(): void
    {
        $app = $this->container();

        $app->scoped('application.unit', static fn (): \stdClass => new \stdClass);

        $manager = $app->make(AuthorizationManager::class);
        $store   = $app->make(LastDecisionStore::class);
        $cache   = $app->make(ResolutionCache::class);
        $tenant  = $app->make(ResolvedTenant::class);
        $state   = PackageState::of($app);
        $unit    = $app->make('application.unit');

        $forgotten = RequestState::abstracts($app);

        foreach (['authorization', LastDecisionStore::class, ResolutionCache::class, ResolvedTenant::class] as $abstract) {
            self::assertContains($abstract, $forgotten);
        }

        self::assertNotContains('application.unit', $forgotten);

        RequestState::forget($app);

        self::assertNotSame($manager, $app->make(AuthorizationManager::class));
        self::assertNotSame($store, $app->make(LastDecisionStore::class));
        self::assertNotSame($cache, $app->make(ResolutionCache::class));
        self::assertNotSame($tenant, $app->make(ResolvedTenant::class));
        self::assertSame($state, PackageState::of($app));
        self::assertSame($unit, $app->make('application.unit'));
    }
}
