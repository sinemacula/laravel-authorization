<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCodec;
use SineMacula\Laravel\Authorization\Cache\ResolutionMemo;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\ResolutionTiers;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Usage\RouteMap;
use SineMacula\Laravel\Authorization\Usage\StoredGrant;
use Tests\Feature\Stubs\FailingCacheStore;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\TestCase;

/**
 * Feature tests for reading and keeping the resolution cache's entries across
 * its two tiers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolutionTiers::class)]
final class ResolutionTiersTest extends TestCase
{
    /** @var string The memo key of the grantee's permissions. */
    private const string MEMO_KEY = 'permissions:user:user-1';

    /** @var string The store key of the grantee's permissions. */
    private const string KEY = 'authorization-test:permissions:user:user-1:platform:every';

    /** @var \Illuminate\Cache\Repository The persistent store behind the tiers. */
    private Repository $repository;

    /** @var \SineMacula\Laravel\Authorization\Cache\VersionedStore The versioned view of the store. */
    private VersionedStore $store;

    /** @var \SineMacula\Laravel\Authorization\Cache\ResolutionMemo The memo behind the tiers. */
    private ResolutionMemo $memo;

    /**
     * Fix the clock and start with an empty store and memo.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-07-01 12:00:00');

        $this->repository = new Repository(new ArrayStore);
        $this->store      = new VersionedStore($this->repository, 'authorization-test');
        $this->memo       = new ResolutionMemo;
    }

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * An entry's key names the kind, the grantee and the scope, under the
     * namespace of the break-glass state it was built in.
     *
     * @return void
     */
    public function testTheKeyNamesTheKindTheGranteeAndTheScope(): void
    {
        self::assertSame(self::KEY, $this->tiers()->key('permissions', self::grantee()));
        self::assertSame('authorization-test:break-glass:permissions:user:user-1:platform:every', $this->tiers(isBreakGlassEnabled: true)->key('permissions', self::grantee()));
    }

    /**
     * A resolution is kept in the memo and, with the versions it pinned, in the
     * store, for the configured maximum, encoded when an encoder is given, and
     * returned as found.
     *
     * @return void
     */
    public function testAResolutionIsKeptInTheMemoAndTheStore(): void
    {
        $pins  = $this->pins();
        $tiers = $this->tiers();

        self::assertSame(['posts:read'], $tiers->keep('permissions', self::grantee(), new Resolution(['posts:read']), $pins, true, null));
        self::assertSame(['posts:read'], $this->memo->get(self::MEMO_KEY));
        self::assertSame(['versions' => $pins->tokens(), 'value' => ['posts:read'], 'until' => Carbon::now()->getTimestamp() + 300], $this->repository->get(self::KEY));

        $tiers->keep('permissions', self::grantee(), new Resolution(['posts:read']), $this->pins(), true, static fn (string $name): string => \strtoupper($name));

        self::assertSame(['POSTS:READ'], $this->stored()['value']);
        self::assertSame(['posts:read'], $this->memo->get(self::MEMO_KEY));
    }

    /**
     * An entry lives no longer than a second before the nearest expiry of a
     * grant it counts, and never longer than the configured maximum.
     *
     * @return void
     */
    public function testAnEntryLivesNoLongerThanTheNearestExpiry(): void
    {
        $now = Carbon::now()->getTimestamp();

        $this->tiers()->keep('permissions', self::grantee(), new Resolution(['posts:read'], 60), $this->pins(), true, null);

        self::assertSame($now + 59, $this->stored()['until']);

        $this->tiers()->keep('permissions', self::grantee(), new Resolution(['posts:read'], 1000), $this->pins(), true, null);

        self::assertSame($now + 300, $this->stored()['until']);

        Carbon::setTestNow(Carbon::now()->addSeconds(300));

        self::assertNull($this->memo->get(self::MEMO_KEY));
    }

    /**
     * A resolution is kept in the memo alone when the records it read changed
     * as it ran, the tenant chain moved, a version could not be pinned, or
     * there is no store.
     *
     * @return void
     */
    public function testAnUnsettledResolutionIsKeptInTheMemoAlone(): void
    {
        $failing = new ResolutionPins(new VersionedStore(new Repository(new FailingCacheStore), 'authorization-test'));

        $failing->grantee(self::grantee());

        $this->tiers()->keep('permissions', self::grantee(), new Resolution(['posts:read'], null, false), $this->pins(), true, null);
        $this->tiers()->keep('permissions', self::grantee(), new Resolution(['posts:read']), $this->pins(), false, null);
        $this->tiers()->keep('permissions', self::grantee(), new Resolution(['posts:read']), $failing, true, null);

        self::assertNull($this->repository->get(self::KEY));
        self::assertSame(['posts:read'], $this->memo->get(self::MEMO_KEY));

        $memoOnly = new ResolutionTiers($this->memo, null, 'authorization-test', 300, false, false);

        self::assertSame(['posts:edit'], $memoOnly->keep('permissions', self::grantee(), new Resolution(['posts:edit']), $this->pins(), true, null));
        self::assertSame(['posts:edit'], $this->memo->get(self::MEMO_KEY));
        self::assertNull($memoOnly->read(self::MEMO_KEY, self::KEY, ResolutionCodec::names(...)));
    }

    /**
     * Given the writes of a bulk read, an entry is added to them under its
     * lifetime rather than written.
     *
     * @return void
     */
    public function testABulkReadsEntryIsAddedToItsWrites(): void
    {
        $pins   = $this->pins();
        $writes = [];

        $this->tiers()->keep('permissions', self::grantee(), new Resolution(['posts:read'], 60), $pins, true, null, $writes);

        self::assertNull($this->repository->get(self::KEY));
        self::assertSame([59 => [self::KEY => ['versions' => $pins->tokens(), 'value' => ['posts:read'], 'until' => Carbon::now()->getTimestamp() + 59]]], $writes);
    }

    /**
     * The routes and the break-glass activations behind an entry are kept
     * beside it, in the memo and the store alike, and read back with it.
     *
     * @return void
     */
    public function testTheRoutesAndActivationsAreKeptBesideTheEntry(): void
    {
        $routes = new RouteMap([new StoredGrant(GrantTarget::ROLE, 'r', new Reference('user', 'u'), 'tenant', 't', null, 9)], [['k', 0]], ['posts:read' => [0]]);
        $tiers  = $this->tiers(isBreakGlassEnabled: true);
        $key    = $tiers->key('permissions', self::grantee());

        $tiers->keep('permissions', self::grantee(), new Resolution(['posts:read'], null, true, $routes, ['posts:read' => ['activation-1']]), $this->pins(), true, null);

        self::assertEquals([$routes], $this->memo->get(ResolutionTiers::ROUTES . self::MEMO_KEY));
        self::assertSame([['posts:read' => ['activation-1']]], $this->memo->get(ResolutionTiers::ACTIVATIONS . self::MEMO_KEY));
        self::assertSame($routes->toArray(), $this->stored($key)['routes'] ?? null);
        self::assertSame(['posts:read' => ['activation-1']], $this->stored($key)['activations'] ?? null);

        $memo  = new ResolutionMemo;
        $fresh = new ResolutionTiers($memo, $this->store, 'authorization-test', 300, false, true);

        self::assertSame(['posts:read'], $fresh->read(self::MEMO_KEY, $key, ResolutionCodec::names(...)));
        self::assertSame(['posts:read'], $memo->get(self::MEMO_KEY));
        self::assertEquals([$routes], $memo->get(ResolutionTiers::ROUTES . self::MEMO_KEY));
        self::assertSame([['posts:read' => ['activation-1']]], $memo->get(ResolutionTiers::ACTIVATIONS . self::MEMO_KEY));
    }

    /**
     * An entry with no routes and no activations stores neither.
     *
     * @return void
     */
    public function testAnEntryWithoutRoutesOrActivationsStoresNeither(): void
    {
        $this->tiers(isBreakGlassEnabled: true)->keep('permissions', self::grantee(), new Resolution(['posts:read']), $this->pins(), true, null);

        $stored = $this->stored('authorization-test:break-glass:permissions:user:user-1:platform:every');

        self::assertArrayNotHasKey('routes', $stored);
        self::assertArrayNotHasKey('activations', $stored);
        self::assertNull($this->memo->get(ResolutionTiers::ROUTES . self::MEMO_KEY));
    }

    /**
     * The activations are kept only for the kinds they are asked about, as kept
     * while usage is tracked, and only while break-glass is enabled.
     *
     * @return void
     */
    public function testActivationsAreKeptForTheAttributedKindsAlone(): void
    {
        $activations = ['posts:read' => ['activation-1']];
        $routed      = ResolutionCodec::kindOf('permissions', true);

        $this->tiers(true, true)->keep($routed, self::grantee(), new Resolution(['posts:read'], null, true, null, $activations), $this->pins(), true, null);
        $this->tiers(true, true)->keep('permissions', self::grantee(), new Resolution(['posts:read'], null, true, null, $activations), $this->pins(), true, null);
        $this->tiers(isBreakGlassEnabled: true)->keep('roles', self::grantee(), new Resolution(['editor'], null, true, null, $activations), $this->pins(), true, null);
        $this->tiers()->keep('policies', self::grantee(), new Resolution([], null, true, null, $activations), $this->pins(), true, null);

        self::assertSame([$activations], $this->memo->get(ResolutionTiers::ACTIVATIONS . $routed . ':user:user-1'));
        self::assertNull($this->memo->get(ResolutionTiers::ACTIVATIONS . self::MEMO_KEY));
        self::assertNull($this->memo->get(ResolutionTiers::ACTIVATIONS . 'roles:user:user-1'));
        self::assertNull($this->memo->get(ResolutionTiers::ACTIVATIONS . 'policies:user:user-1'));
    }

    /**
     * A stored entry is read back into the memo for the rest of its life, and
     * not once a version it recorded has changed.
     *
     * @return void
     */
    public function testAStoredEntryIsReadBackWhileItsVersionsHold(): void
    {
        $this->tiers()->keep('permissions', self::grantee(), new Resolution(['posts:read'], 60), $this->pins(), true, null);

        $memo  = new ResolutionMemo;
        $tiers = new ResolutionTiers($memo, $this->store, 'authorization-test', 300, false, false);

        self::assertSame(['posts:read'], $tiers->read(self::MEMO_KEY, self::KEY, ResolutionCodec::names(...)));
        self::assertSame(['posts:read'], $memo->get(self::MEMO_KEY));

        $this->store->bump([$this->store->granteeKey(self::grantee())]);

        $fresh = new ResolutionMemo;

        self::assertNull((new ResolutionTiers($fresh, $this->store, 'authorization-test', 300, false, false))->read(self::MEMO_KEY, self::KEY, ResolutionCodec::names(...)));
        self::assertNull($fresh->get(self::MEMO_KEY));

        Carbon::setTestNow(Carbon::now()->addSeconds(59));

        self::assertNull($memo->get(self::MEMO_KEY));
    }

    /**
     * Given the entries a bulk read found, the entry is taken from those, its
     * versions already checked, without reading the store again.
     *
     * @return void
     */
    public function testABulkReadTakesTheEntryFromThoseFound(): void
    {
        $pins = $this->pins();

        $this->tiers()->keep('permissions', self::grantee(), new Resolution(['posts:read']), $pins, true, null);
        $this->store->bump([$this->store->granteeKey(self::grantee())]);

        $tiers = new ResolutionTiers(new ResolutionMemo, $this->store, 'authorization-test', 300, false, false);
        $found = [self::KEY => ['versions' => $pins->tokens(), 'value' => ['posts:edit'], 'until' => Carbon::now()->getTimestamp() + 300]];

        self::assertSame(['posts:edit'], $tiers->read(self::MEMO_KEY, self::KEY, ResolutionCodec::names(...), $found));
        self::assertNull($tiers->read(self::MEMO_KEY, self::KEY, ResolutionCodec::names(...), []));
    }

    /**
     * A stored entry past its until is not served while the store holds it.
     *
     * @return void
     */
    public function testALapsedEntryIsNotReadBack(): void
    {
        $this->tiers()->keep('permissions', self::grantee(), new Resolution(['posts:read'], 60), $this->pins(), true, null);
        $this->repository->put(self::KEY, $this->stored(), 600);

        Carbon::setTestNow(Carbon::now()->addSeconds(60));

        $tiers = new ResolutionTiers(new ResolutionMemo, $this->store, 'authorization-test', 300, false, false);

        self::assertNull($tiers->read(self::MEMO_KEY, self::KEY, ResolutionCodec::names(...)));
    }

    /**
     * An entry a bulk read found is not served once its until is reached.
     *
     * @return void
     */
    public function testABulkReadSkipsALapsedEntry(): void
    {
        $tiers = new ResolutionTiers(new ResolutionMemo, $this->store, 'authorization-test', 300, false, false);
        $found = [self::KEY => ['versions' => $this->pins()->tokens(), 'value' => ['posts:read'], 'until' => Carbon::now()->getTimestamp()]];

        self::assertNull($tiers->read(self::MEMO_KEY, self::KEY, ResolutionCodec::names(...), $found));
    }

    /**
     * An entry that cannot be read back is discarded, with a warning naming it,
     * and leaves the memo as it was.
     *
     * @return void
     */
    public function testACorruptEntryIsDiscardedWithAWarning(): void
    {
        $logger = new RecordingLogger;

        $this->app?->instance('log', $logger);

        $this->tiers()->keep('permissions', self::grantee(), new Resolution(['posts:read']), $this->pins(), true, null);

        foreach ([['value' => [42]], ['routes' => 'not routes'], ['activations' => 'not activations']] as $corruption) {
            $this->repository->put(self::KEY, [...$this->stored(), 'value' => ['posts:read'], ...$corruption], 60);

            $memo = new ResolutionMemo;

            self::assertNull((new ResolutionTiers($memo, $this->store, 'authorization-test', 300, false, false))->read(self::MEMO_KEY, self::KEY, ResolutionCodec::names(...)));
            self::assertNull($memo->get(self::MEMO_KEY));
            self::assertNull($memo->get(ResolutionTiers::ROUTES . self::MEMO_KEY));
        }

        self::assertCount(3, $logger->records);
        self::assertSame('Authorization: discarding corrupt resolution-cache entry \'' . self::KEY . '\' — Cached name is not a string.', $logger->messages()[0]);
        self::assertSame(['cache_key' => self::KEY, 'reason' => 'Cached name is not a string.'], $logger->records[0]['context']);
    }

    /**
     * Return tiers over the test's memo and store.
     *
     * @param  bool  $isTrackingUsage
     * @param  bool  $isBreakGlassEnabled
     * @return \SineMacula\Laravel\Authorization\Cache\ResolutionTiers
     */
    private function tiers(bool $isTrackingUsage = false, bool $isBreakGlassEnabled = false): ResolutionTiers
    {
        return new ResolutionTiers($this->memo, $this->store, 'authorization-test', 300, $isTrackingUsage, $isBreakGlassEnabled);
    }

    /**
     * Return pins of the grantee and the tenant chain in the test's store.
     *
     * @return \SineMacula\Laravel\Authorization\Cache\ResolutionPins
     */
    private function pins(): ResolutionPins
    {
        $pins = new ResolutionPins($this->store);

        $pins->grantee(self::grantee());
        $pins->isChainHeldOncePinned();

        return $pins;
    }

    /**
     * Return the entry stored under the key.
     *
     * @param  string  $key
     * @return array<string, mixed>
     */
    private function stored(string $key = self::KEY): array
    {
        $entry = $this->repository->get($key);

        self::assertIsArray($entry);

        /** @var array<string, mixed> $entry */
        return $entry;
    }

    /**
     * Return the grantee every test keeps entries for.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function grantee(): Reference
    {
        return new Reference('user', 'user-1');
    }
}
