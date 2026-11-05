<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\FailingCacheStore;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\TestCase;

/**
 * Feature tests for the version tokens a resolution pins as it runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolutionPins::class)]
final class ResolutionPinsTest extends TestCase
{
    /**
     * The grantee, roles and policies are pinned under their own keys, in the
     * order they were pinned.
     *
     * @return void
     */
    public function testPinsRecordEachKindUnderItsKey(): void
    {
        $store = new VersionedStore(new Repository(new ArrayStore), 'authz');
        $pins  = new ResolutionPins($store);

        $pins->grantee(new Reference('user', 'user-1'));
        $pins->roles(['role-1', 'role-2']);
        $pins->policies(['policy-1']);
        $pins->roles([]);

        self::assertSame([
            'authz:version:grantee:user:user-1',
            'authz:version:role:role-1',
            'authz:version:role:role-2',
            'authz:version:policy:policy-1',
        ], \array_keys($pins->tokens()));
        self::assertSame($store->tokens(\array_keys($pins->tokens())), $pins->tokens());
        self::assertTrue($pins->isComplete());
    }

    /**
     * Without a store nothing is pinned, and the pins stay complete.
     *
     * @return void
     */
    public function testWithoutAStoreNothingIsPinned(): void
    {
        $pins = new ResolutionPins;

        $pins->grantee(new Reference('user', 'user-1'));
        $pins->roles(['role-1']);
        $pins->policies(['policy-1']);

        self::assertSame([], $pins->tokens());
        self::assertTrue($pins->isComplete());
    }

    /**
     * Pinning no roles asks the store nothing.
     *
     * @return void
     */
    public function testPinningNothingAsksTheStoreNothing(): void
    {
        $driver = new FailingCacheStore;
        $pins   = new ResolutionPins(new VersionedStore(new Repository($driver), 'authz'));

        $pins->roles([]);
        $pins->policies([]);

        self::assertSame(0, $driver->calls);
        self::assertTrue($pins->isComplete());
    }

    /**
     * A pin the store cannot read leaves the pins incomplete, so the resolution
     * is not stored.
     *
     * @return void
     */
    public function testAFailedPinLeavesThePinsIncomplete(): void
    {
        $this->app?->instance('log', new RecordingLogger);

        $pins = new ResolutionPins(new VersionedStore(new Repository(new FailingCacheStore), 'authz'));

        $pins->roles(['role-1']);

        self::assertSame([], $pins->tokens());
        self::assertFalse($pins->isComplete());
    }
}
