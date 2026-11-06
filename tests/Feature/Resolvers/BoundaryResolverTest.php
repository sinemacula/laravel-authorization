<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\BoundaryResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the resolution of the permission boundaries of a grantee
 * that apply to a check: those whose scope covers the tenant the check is
 * decided in, read in one query, through the resolution cache.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(BoundaryResolver::class)]
final class BoundaryResolverTest extends TestCase
{
    use ActsAsTenant;

    /**
     * A grantee with no boundary has none, and a subject that is not a saved
     * authorizable identity has none and costs no query.
     *
     * @return void
     */
    public function testAGranteeWithoutABoundaryHasNone(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        self::assertSame([], BoundaryResolver::boundariesFor($user));

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertSame([], BoundaryResolver::boundariesFor(null));
        self::assertSame([], BoundaryResolver::boundariesFor(new \stdClass));
        self::assertSame([], BoundaryResolver::boundariesFor(new StubIdentity(['id' => 'unsaved'])));
        self::assertSame([], BoundaryResolver::boundariesFor(new Reference('user', 'user-1')));
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * Only the boundaries whose scope covers the check's tenant apply: the
     * platform's everywhere, the tenant's own in it, an ancestor's that reaches
     * below, and never a sibling's or one limited to its own tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheBoundariesOfTheScopeApply(): void
    {
        [$org, $account, $sibling, $closed] = \array_map(self::createTenant(...), ['org', 'account', 'sibling', 'closed']);

        $tree = (new StubTenantTree)->put(Reference::of($account), Reference::of($org))->put(Reference::of($sibling), Reference::of($org));

        $this->app?->instance(TenantTree::class, $tree->put(Reference::of($closed), Reference::of($account)));

        $user = StubIdentity::create(['id' => 'user-1']);

        self::service()->set($user, self::cap('platform'));
        self::service()->set($user, self::cap('in-org'), $org);
        self::service()->set($user, self::cap('in-account'), $account, false);
        self::service()->set($user, self::cap('in-sibling'), $sibling);

        self::assertSame(['platform'], self::names($user));
        self::assertSame(['in-org', 'platform'], TenantScope::within($org, null, static fn (): array => self::names($user)));
        self::assertSame(['in-account', 'in-org', 'platform'], TenantScope::within($account, null, static fn (): array => self::names($user)));
        self::assertSame(['in-org', 'platform'], TenantScope::within($closed, null, static fn (): array => self::names($user)));
        self::assertSame(['in-org', 'in-sibling', 'platform'], TenantScope::within($sibling, null, static fn (): array => self::names($user)));
    }

    /**
     * A grantee's boundaries are its own: another grantee's never apply.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherGranteesBoundariesDoNotApply(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $other = StubIdentity::create(['id' => 'user-2']);

        self::service()->set($other, self::cap('theirs'));

        self::assertSame([], self::names($user));
        self::assertSame(['theirs'], self::names($other));
    }

    /**
     * A policy set as the boundary in more than one scope is read once, with
     * its stored key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicySetInTwoScopesIsReadOnce(): void
    {
        $tenant = self::createTenant('tenant-a');
        $user   = StubIdentity::create(['id' => 'user-1']);
        $cap    = self::cap('both');

        self::service()->set($user, $cap);
        self::service()->set($user, $cap, $tenant);

        $boundaries = TenantScope::within($tenant, null, static fn (): array => BoundaryResolver::boundariesFor($user));

        self::assertCount(1, $boundaries);
        self::assertSame($cap->id, $boundaries[0]->id);
        self::assertNull($boundaries[0]->resource);
    }

    /**
     * The boundaries and their documents are read in one query, and read again
     * in the request they ask nothing more.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReadsInOneQueryThenFromTheCache(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        self::service()->set($user, self::cap('cap'));

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertSame(['cap'], self::names($user));
        self::assertCount(1, DB::getQueryLog());

        DB::flushQueryLog();

        self::assertSame(['cap'], self::names($user));
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * Without a resolution cache bound, the boundaries are read straight from
     * the database.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReadsFromTheDatabaseWithoutACache(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        self::service()->set($user, self::cap('cap'));

        $this->app?->forgetInstance(ResolutionCache::class);
        $this->app?->offsetUnset(ResolutionCache::class);

        self::assertSame(['cap'], self::names($user));
    }

    /**
     * With a persistent store, the boundaries are kept across requests, read
     * afresh once the grantee's boundary changes or any policy is rewritten.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPersistentEntryHoldsUntilAWriteChangesIt(): void
    {
        $store = new Repository(new ArrayStore);
        $user  = StubIdentity::create(['id' => 'user-1']);
        $cap   = self::cap('cap');

        self::request($store);
        self::service()->set($user, $cap);

        self::assertSame(['cap'], self::names($user));

        self::request($store);

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertSame(['cap'], self::names($user));
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();

        $cap->update(['document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:edit']]]]]);
        self::request($store);

        self::assertSame(['posts:edit'], BoundaryResolver::boundariesFor($user)[0]->statements[0]->actions);

        self::service()->set($user, self::cap('other'));
        self::request($store);

        self::assertSame(['other'], self::names($user));
    }

    /**
     * The resolution pins the version every boundary entry shares before it
     * reads, and lists each boundary for evaluation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheResolutionPinsTheSharedVersion(): void
    {
        $versions = new VersionedStore(new Repository(new ArrayStore), 'authz');
        $pins     = new ResolutionPins($versions);
        $user     = StubIdentity::create(['id' => 'user-1']);

        self::service()->set($user, self::cap('cap'));

        $resolution = BoundaryResolver::resolve(Reference::of($user), $pins);

        self::assertSame(['authz:version:boundaries'], \array_keys($pins->tokens()));
        self::assertSame(['cap'], \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $resolution->value));
        self::assertNull($resolution->expiresIn);
        self::assertTrue($resolution->stable);
    }

    /**
     * A boundary whose document cannot be read is never skipped: its exception
     * is thrown, so it denies every check for the grantee.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnreadableBoundaryIsThrown(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $cap  = self::cap('cap');

        self::service()->set($user, $cap);

        DB::table('policies')->where('id', $cap->getKey())->update(['document' => '{"statements": "broken"}']);

        $this->expectException(InvalidPolicyDocumentException::class);

        BoundaryResolver::boundariesFor($user);
    }

    /**
     * Start a new request with the store as the persistent tier.
     *
     * @param  \Illuminate\Cache\Repository  $store
     * @return void
     */
    private static function request(Repository $store): void
    {
        app()->instance(ResolutionCache::class, new ResolutionCache($store, 300, 'authz'));
    }

    /**
     * Return the names of the grantee's boundaries in the current scope,
     * sorted.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $grantee
     * @return list<string>
     */
    private static function names(StubIdentity $grantee): array
    {
        $names = \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, BoundaryResolver::boundariesFor($grantee));

        \sort($names);

        return $names;
    }

    /**
     * Create a boundary policy allowing `posts:read`.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function cap(string $name): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);
    }

    /**
     * Return the boundary service, as the container binds it.
     *
     * @return \SineMacula\Laravel\Authorization\Services\BoundaryService
     */
    private static function service(): BoundaryService
    {
        $service = BoundaryService::instance();

        self::assertInstanceOf(BoundaryService::class, $service);

        return $service;
    }
}
