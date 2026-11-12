<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Models\BreakGlassActivation;
use SineMacula\Laravel\Authorization\Observers\BreakGlassActivationObserver;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the observer bumping a break-glass activation's grantee
 * whenever the activation is saved or deleted through the model: the grantee it
 * names, and the one it named before a move, at once and again once the
 * caller's transaction commits, and nothing at all without a resolution cache.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BreakGlassActivationObserver::class)]
final class BreakGlassActivationObserverTest extends TestCase
{
    use ActivatesBreakGlass;

    /** @var \Illuminate\Cache\Repository The store every request of the test shares. */
    private Repository $store;

    /**
     * Give every request of the test one store.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->store = new Repository(new ArrayStore);
    }

    /**
     * Creating, updating, moving and deleting an activation each bump the
     * versions of the grantees it names and named, and empty the memo, and
     * nobody else's.
     *
     * @return void
     */
    public function testEveryChangeBumpsItsGrantees(): void
    {
        $ann      = StubIdentity::create(['id' => 'ann']);
        $bob      = StubIdentity::create(['id' => 'bob']);
        $carol    = Reference::of(StubIdentity::create(['id' => 'carol']));
        $cache    = $this->request();
        $versions = new VersionedStore($this->store, 'observer-test');
        $grantees = [Reference::of($ann), Reference::of($bob), $carol];
        $tokens   = fn (): array => \array_map(fn (Reference $grantee): mixed => $this->store->get($versions->granteeKey($grantee)), $grantees);

        $cache->rememberPermissions($ann, static fn (): Resolution => new Resolution(['posts:read']));

        [$annBefore, $bobBefore, $carolBefore] = $tokens();

        $activation = self::activate($ann, self::emergencyRole());

        [$annCreated, $bobCreated] = $tokens();

        self::assertNotSame($annBefore, $annCreated);
        self::assertSame($bobBefore, $bobCreated);
        self::assertSame([$versions->granteeKey(Reference::of($ann))], self::granteeVersions($this->store));
        self::assertSame(['posts:edit'], $cache->rememberPermissions($ann, static fn (): Resolution => new Resolution(['posts:edit'])));

        $activation->update(['justification' => 'outage']);

        [$annUpdated] = $tokens();

        self::assertNotSame($annCreated, $annUpdated);

        $activation->update(['authorizable_id' => 'bob']);

        [$annMoved, $bobMoved, $carolMoved] = $tokens();

        self::assertNotSame($annUpdated, $annMoved);
        self::assertNotSame($bobCreated, $bobMoved);
        self::assertSame($carolBefore, $carolMoved);

        $activation->delete();

        [$annDeleted, $bobDeleted] = $tokens();

        self::assertSame($annMoved, $annDeleted);
        self::assertNotSame($bobMoved, $bobDeleted);
    }

    /**
     * Inside a transaction the versions are bumped at once and again once it
     * commits, so an entry stored before the commit never holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheVersionsAreBumpedAgainOnceTheTransactionCommits(): void
    {
        $ann      = StubIdentity::create(['id' => 'ann']);
        $role     = self::emergencyRole();
        $versions = new VersionedStore($this->store, 'observer-test');
        $key      = $versions->granteeKey(Reference::of($ann));

        $this->request();

        $tokens = DB::transaction(function () use ($ann, $role, $key): array {
            self::activate($ann, $role);

            return [$this->store->get($key)];
        });

        $tokens[] = $this->store->get($key);

        self::assertNotNull($tokens[0]);
        self::assertNotSame($tokens[0], $tokens[1]);
    }

    /**
     * Without a resolution cache bound, a change bumps nothing and still saves.
     *
     * @return void
     */
    public function testNothingIsBumpedWithoutACache(): void
    {
        $ann = StubIdentity::create(['id' => 'ann']);

        $this->app?->offsetUnset(ResolutionCache::class);

        self::assertNull(ResolutionCache::instance());

        $activation = self::activate($ann, self::emergencyRole());

        $activation->delete();

        self::assertSame(0, BreakGlassActivation::query()->count());
        self::assertNull($this->store->get((new VersionedStore($this->store, 'observer-test'))->granteeKey(Reference::of($ann))));
    }

    /**
     * The columns of a grantee, and the grantee they name: none unless both are
     * set, and a numeric key as text.
     *
     * @return iterable<string, array{mixed, mixed, list<string>|null}>
     */
    public static function namingColumns(): iterable
    {
        yield 'neither set' => [null, null, null];
        yield 'no key' => ['user', null, null];
        yield 'no type' => [null, 'ann', null];
        yield 'a numeric key' => ['user', 5, ['user', '5']];
    }

    /**
     * A grantee is named only when both its columns are set, as they are once
     * an activation has been saved.
     *
     * @param  mixed  $type
     * @param  mixed  $id
     * @param  list<string>|null  $expected
     * @return void
     */
    #[DataProvider('namingColumns')]
    public function testAGranteeIsNamedByBothColumns(mixed $type, mixed $id, ?array $expected): void
    {
        $grantee = (new \ReflectionMethod(BreakGlassActivationObserver::class, 'grantee'))->invoke(null, $type, $id);

        self::assertSame($expected, $grantee instanceof Reference ? [$grantee->type, $grantee->id] : $grantee);
    }

    /**
     * Start a request with a resolution cache over the test's store.
     *
     * @return \SineMacula\Laravel\Authorization\Cache\ResolutionCache
     */
    private function request(): ResolutionCache
    {
        $cache = new ResolutionCache($this->store, 300, 'observer-test');

        $this->app?->instance(ResolutionCache::class, $cache);

        return $cache;
    }

    /**
     * Return the keys of the grantee versions the store holds.
     *
     * @param  \Illuminate\Cache\Repository  $store
     * @return list<string>
     */
    private static function granteeVersions(Repository $store): array
    {
        /** @var \Illuminate\Cache\ArrayStore $array */
        $array   = $store->getStore();
        $storage = (new \ReflectionProperty($array, 'storage'))->getValue($array);

        self::assertIsArray($storage);

        return \array_values(\array_filter(\array_map(\strval(...), \array_keys($storage)), static fn (string $key): bool => \str_contains($key, ':version:grantee:')));
    }
}
