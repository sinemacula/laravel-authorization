<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use Tests\TestCase;

/**
 * Feature coverage for the centralised service-locator accessors
 * (`ResolutionCache::instance()` and `AuthorizationManager::instance()`).
 *
 * These replace the ad-hoc `app()->bound(...) ? app(...) : null` pattern
 * that previously lived in every model trait and the Blade helper. The
 * accessors are the single sanctioned service-locator site in the
 * package — consumers unable to take the collaborator via constructor
 * injection (model traits, static Blade helpers) funnel through here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolutionCache::class)]
#[CoversClass(AuthorizationManager::class)]
final class ContainerInstanceAccessorsTest extends TestCase
{
    /**
     * When the service provider has bound the cache, the accessor
     * returns the singleton the container hands back.
     *
     * @return void
     */
    public function testResolutionCacheInstanceReturnsBoundSingleton(): void
    {
        self::assertNotNull($this->app);

        $bound = $this->app->make(ResolutionCache::class);

        $resolved = ResolutionCache::instance();

        self::assertSame($bound, $resolved);
    }

    /**
     * When the container has no binding for the cache, the accessor
     * returns null — the same fail-soft contract the model traits
     * rely on so unbound Eloquent models keep working without a
     * cache tier.
     *
     * @return void
     */
    public function testResolutionCacheInstanceReturnsNullWhenUnbound(): void
    {
        $this->withBareContainer(static function (): void {
            self::assertNull(ResolutionCache::instance());
        });
    }

    /**
     * When the service provider has bound the manager, the accessor
     * returns the singleton the container hands back.
     *
     * @return void
     */
    public function testAuthorizationManagerInstanceReturnsBoundSingleton(): void
    {
        self::assertNotNull($this->app);

        $bound = $this->app->make(AuthorizationManager::class);

        $resolved = AuthorizationManager::instance();

        self::assertSame($bound, $resolved);
    }

    /**
     * When the container has no binding for the manager, the accessor
     * returns null — the same fail-soft contract the Blade helper
     * relies on so unbound views render without a principal rather
     * than raising a runtime error.
     *
     * @return void
     */
    public function testAuthorizationManagerInstanceReturnsNullWhenUnbound(): void
    {
        $this->withBareContainer(static function (): void {
            self::assertNull(AuthorizationManager::instance());
        });
    }

    /**
     * Swap the active container for a bare instance for the duration
     * of the callback, then restore the original. Lets the unbound
     * paths of the static accessors be exercised without having to
     * surgically unbind individual keys on the Testbench container
     * (which also carries package aliases that would keep `bound()`
     * positive).
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function withBareContainer(\Closure $callback): void
    {
        $previous = Container::getInstance();

        Container::setInstance(new Container);

        try {
            $callback();
        } finally {
            Container::setInstance($previous);
        }
    }
}
