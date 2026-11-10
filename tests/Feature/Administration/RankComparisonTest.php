<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\RankComparison;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\RolesOnlyPrincipal;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `RankComparison`, the one comparison of rank delegated
 * administration makes (N76).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RankComparison::class)]
final class RankComparisonTest extends TestCase
{
    use ActsAsTenant;

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
     * Seniority is strict: a smaller rank acts on a larger one, never the other
     * way round, and an equal rank refuses both ways; each side's rank is the
     * most senior of the roles it holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSeniorityIsStrict(): void
    {
        $senior = self::holding('senior', 1, 9);
        $junior = self::holding('junior', 5);
        $equal  = self::holding('equal', 1);

        self::assertSame(1, RankComparison::rankOf($senior));
        self::assertTrue(RankComparison::canActOn($senior, $junior));
        self::assertFalse(RankComparison::canActOn($junior, $senior));
        self::assertFalse(RankComparison::canActOn($senior, $equal));
        self::assertFalse(RankComparison::canActOn($equal, $senior));
    }

    /**
     * A target holding no ranked role is the most junior, and an actor holding
     * none acts on no one, an unranked target included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheUnrankedAreTheMostJunior(): void
    {
        $ranked   = self::holding('ranked', 3);
        $unranked = self::holding('unranked', null);
        $bare     = StubIdentity::create(['id' => 'bare']);

        self::assertNull(RankComparison::rankOf($unranked));
        self::assertNull(RankComparison::rankOf($bare));
        self::assertTrue(RankComparison::canActOn($ranked, $unranked));
        self::assertTrue(RankComparison::canActOn($ranked, $bare));
        self::assertFalse(RankComparison::canActOn($unranked, $ranked));
        self::assertFalse(RankComparison::canActOn($unranked, $bare));
        self::assertFalse(RankComparison::canActOn($bare, $unranked));
    }

    /**
     * A side whose roles cannot be read cannot be compared, so the comparison
     * fails closed, whatever the other's rank.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASideThatHoldsNoRolesCannotBeCompared(): void
    {
        $ranked = self::holding('ranked', 0);

        self::assertFalse(RankComparison::isComparable(new \stdClass));
        self::assertTrue(RankComparison::isComparable($ranked));
        self::assertNull(RankComparison::rankOf(new \stdClass));
        self::assertFalse(RankComparison::canActOn($ranked, new \stdClass));
        self::assertFalse(RankComparison::canActOn(new \stdClass, $ranked));
    }

    /**
     * A holder's rank is the most senior of its ranked roles, whatever unranked
     * roles it holds as well, before or after them, so an actor that holds a
     * ranked role among unranked ones acts on an unranked target.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testUnrankedRolesAmongRankedOnesAreSkipped(): void
    {
        $mixed = self::holding('mixed', null, 3, null);

        self::assertSame(3, RankComparison::rankOf($mixed));
        self::assertTrue(RankComparison::canActOn($mixed, self::holding('unranked', null)));
    }

    /**
     * A holder is compared only when it both supports roles and holds them
     * through the package's role relation: one that supports roles without the
     * relation, and one with a `roles()` method that does not support roles,
     * have no rank and cannot be compared, whatever that method returns.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyAHolderOfThePackagesRolesIsCompared(): void
    {
        $ranked = self::holding('ranked', 0);
        $boss   = Role::create(['name' => 'boss', 'rank' => 0]);
        $roles  = new class ($boss) {
            /**
             * Create a holder of the role, which does not support roles.
             *
             * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
             */
            public function __construct(

                /** The role its query finds. */
                private readonly Role $role,
            ) {}

            /**
             * Return a query whose results are the role.
             *
             * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authorization\Models\Role>
             */
            public function roles(): Builder
            {
                return Role::query()->whereKey($this->role->id);
            }
        };

        foreach ([new RolesOnlyPrincipal, $roles] as $holder) {
            self::assertFalse(RankComparison::isComparable($holder));
            self::assertNull(RankComparison::rankOf($holder));
            self::assertFalse(RankComparison::canActOn($ranked, $holder));
            self::assertFalse(RankComparison::canActOn($holder, $ranked));
        }
    }

    /**
     * With rank turned off, rank is no constraint: every comparison passes, an
     * uncomparable side included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithRankOffEveryComparisonPasses(): void
    {
        $junior = self::holding('junior', 5);
        $senior = self::holding('senior', 1);

        $this->container()->make(ConfigRepository::class)->set('authorization.rank.enabled', false);

        self::assertTrue(RankComparison::canActOn($junior, $senior));
        self::assertTrue(RankComparison::canActOn(new \stdClass, $senior));
    }

    /**
     * A grant that has expired, or that holds in another application or tenant
     * than the scope, never counts, for either side, through the same path.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheGrantsOfTheScopeCount(): void
    {
        $tenant = self::createTenant('tenant-a');
        $actor  = self::holding('actor', 2);
        $target = StubIdentity::create(['id' => 'target']);

        $target->assignRole(Role::create(['name' => 'expiring', 'rank' => 0]), Carbon::now()->addHour());
        $target->assignRole(Role::create(['name' => 'mobile-boss', 'rank' => 0]), application: 'mobile');
        $target->assignRole(Role::create(['name' => 'tenant-boss', 'rank' => 0]), tenant: $tenant);

        self::assertFalse(RankComparison::canActOn($actor, $target));

        Carbon::setTestNow(Carbon::now()->addHours(2));

        self::assertTrue(RankComparison::canActOn($actor, $target));
        self::assertFalse(RankComparison::canActOn($actor, $target, AuthorizationScope::platform('mobile')));
        self::assertFalse(RankComparison::canActOn($actor, $target, AuthorizationScope::tenant($tenant)));
        self::assertTrue(RankComparison::canActOn($actor, $target, AuthorizationScope::platform('admin')));
        self::assertTrue(RankComparison::canActOn($actor, $this->fresh($target)));
    }

    /**
     * The identity's own `canActOn()` returns the comparison alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityHelperReturnsTheComparison(): void
    {
        $senior = self::holding('senior', 1);
        $junior = self::holding('junior', 2);

        self::assertTrue($senior->canActOn($junior));
        self::assertFalse($junior->canActOn($senior));
        self::assertFalse($senior->canActOn(new \stdClass));
    }

    /**
     * The rank of a role a change would grant the target counts as the
     * target's: a grant leaving it equal to or senior to the actor is refused,
     * and one leaving it junior is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRankGrantedCountsAsTheTargets(): void
    {
        $actor  = self::holding('actor', 3);
        $target = self::holding('target', 7);

        self::assertTrue(RankComparison::canActOn($actor, $target));
        self::assertTrue(RankComparison::canActOn($actor, $target, null, 4));
        self::assertFalse(RankComparison::canActOn($actor, $target, null, 3));
        self::assertFalse(RankComparison::canActOn($actor, $target, null, 1));
        self::assertTrue(RankComparison::canActOn($actor, StubIdentity::create(['id' => 'bare']), null, 9));
        self::assertFalse(RankComparison::canActOn($actor, StubIdentity::query()->findOrFail('bare'), null, 2));
    }

    /**
     * An actor given as a resolved subject holds the roles that reach it in a
     * check: its principal's, and its identity's when the identity grants to
     * it, the most senior counting; it is comparable when either side is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubjectActorHoldsItsPrincipalsAndIdentitysRoles(): void
    {
        $principal = self::holding('principal', 6);
        $identity  = self::holding('identity', 2);
        $target    = self::holding('target', 4);
        $subject   = new Subject($principal, $identity);

        self::assertSame(2, RankComparison::rankOf($subject));
        self::assertTrue(RankComparison::isComparable($subject));
        self::assertTrue(RankComparison::canActOn($subject, $target));
        self::assertFalse(RankComparison::canActOn($principal, $target));
        self::assertSame(6, RankComparison::rankOf(new Subject($principal, $principal)));
        self::assertSame(2, RankComparison::rankOf(new Subject(new \stdClass, $identity)));
        self::assertTrue(RankComparison::isComparable(new Subject(new \stdClass, $identity)));
        self::assertFalse(RankComparison::isComparable(new Subject(new \stdClass)));
        self::assertNull(RankComparison::rankOf(new Subject(new \stdClass)));
    }

    /**
     * A senior principal acting through a junior granting identity keeps its
     * principal's rank.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASeniorPrincipalKeepsItsRankThroughAJuniorIdentity(): void
    {
        $principal = self::holding('senior-principal', 1);
        $identity  = self::holding('junior-identity', 5);
        $middle    = self::holding('mid', 3);

        self::assertSame(1, RankComparison::rankOf(new Subject($principal, $identity)));
        self::assertTrue(RankComparison::canActOn(new Subject($principal, $identity), $middle));
    }

    /**
     * Roles are read on the write connection, so a replica that lags never
     * makes a screen and the service compare different rows.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testRolesAreReadOnTheWriteConnection(): void
    {
        $actor  = self::holding('actor', 1);
        $target = self::holding('target', 4);

        /** @var \Illuminate\Database\Connection $connection */
        $connection = $actor->getConnection();

        $connection->setReadPdo(static fn (): never => throw new \LogicException('The read connection was used.'));

        try {
            self::assertTrue(RankComparison::canActOn($this->fresh($actor), $this->fresh($target)));
            self::assertSame(4, RankComparison::rankAcross($target, GrantScope::platform()));
        } finally {
            $connection->setReadPdo(null);
        }
    }

    /**
     * Across a grant's reach, the target's most senior live, ranked role
     * counts: held platform-wide, in a tenant of the reach, and, for a grant to
     * every application, in any application; an expired role, one of another
     * holder, one without a rank and one outside the reach never count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTargetsRankIsReadAcrossTheReach(): void
    {
        $target = self::holding('target', 7, null);
        $tenant = new Reference('tenant', 'a');
        $grants = GrantService::instance();

        self::assertSame(7, RankComparison::rankAcross($target, GrantScope::platform()));
        self::assertNull(RankComparison::rankAcross(self::holding('nobody', null), GrantScope::platform()));

        $grants?->grantRole(self::holding('other'), Role::create(['name' => 'theirs', 'rank' => 0]));
        $grants?->grantRole(new Reference('stub-other', 'target'), Role::create(['name' => 'same-key', 'rank' => 0]));
        $grants?->grantRole($target, Role::create(['name' => 'gone', 'rank' => 0]), Carbon::now()->addMinute());

        Carbon::setTestNow(Carbon::now()->addHour());

        self::assertSame(7, RankComparison::rankAcross($target, GrantScope::platform()));

        $grants?->grantRole($target, Role::create(['name' => 'local', 'rank' => 3]), tenant: $tenant);
        $grants?->grantRole($target, Role::create(['name' => 'billing', 'rank' => 2]), application: 'billing');

        self::assertSame(2, RankComparison::rankAcross($target, GrantScope::platform()));
        self::assertSame(3, RankComparison::rankAcross($target, new GrantScope($tenant, 'admin')));
        self::assertSame(2, RankComparison::rankAcross($target, new GrantScope($tenant, 'billing')));
        self::assertSame(7, RankComparison::rankAcross($target, new GrantScope(new Reference('tenant', 'b'), 'admin')));

        $owned = Role::query()->withoutGlobalScopes()->create(['name' => 'owned', 'rank' => 1, 'tenant_type' => 'tenant', 'tenant_id' => 'a']);

        $grants?->grantRole($target, $owned, tenant: $tenant);

        self::assertSame(1, RankComparison::rankAcross($target, new GrantScope($tenant, 'admin')));
    }

    /**
     * Across a reach, the most senior rank any of several holders holds counts,
     * read in one query whatever their types; none for no holders, or holders
     * with no ranked role there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheHoldersRankIsReadAcrossTheReachInOneQuery(): void
    {
        $tenant = new Reference('tenant', 'a');
        $junior = self::holding('junior', 7);
        $senior = self::holding('senior', null);

        GrantService::instance()?->grantRole($senior, Role::create(['name' => 'local', 'rank' => 2]), tenant: $tenant);
        GrantService::instance()?->grantRole(new Reference('stub-other', 'other'), Role::create(['name' => 'other', 'rank' => 1]));

        $holders = [Reference::of($junior), Reference::of($senior), new Reference('stub-other', 'other')];

        self::assertSame(1, RankComparison::rankAcrossAll($holders, GrantScope::platform()));
        self::assertSame(2, RankComparison::rankAcrossAll([Reference::of($junior), Reference::of($senior)], new GrantScope($tenant)));
        self::assertSame(7, RankComparison::rankAcrossAll([Reference::of($junior), Reference::of($senior)], new GrantScope(new Reference('tenant', 'b'))));
        self::assertNull(RankComparison::rankAcrossAll([], GrantScope::platform()));
        self::assertNull(RankComparison::rankAcrossAll([new Reference('stub-other', 'nobody')], GrantScope::platform()));

        DB::enableQueryLog();

        RankComparison::rankAcrossAll($holders, GrantScope::platform());

        self::assertCount(1, DB::getQueryLog());
    }

    /**
     * An actor is ranked in the tenant and application given, or at platform
     * scope for none; a holder's type can be ranked when it names a model whose
     * roles can be read, by its class or by its morph alias.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheActorIsRankedInTheGrantsOwnScope(): void
    {
        $tenant = new Reference('tenant', 'a');
        $actor  = self::holding('actor', 6);

        GrantService::instance()?->grantRole($actor, Role::create(['name' => 'local', 'rank' => 3]), tenant: $tenant);
        GrantService::instance()?->grantRole($actor, Role::create(['name' => 'billing', 'rank' => 1]), application: 'billing');

        self::assertSame(6, RankComparison::rankIn(new Subject($actor, $actor), null, 'admin'));
        self::assertSame(3, RankComparison::rankIn(new Subject($actor, $actor), $tenant, 'admin'));
        self::assertSame(1, RankComparison::rankIn(new Subject($actor, $actor), $tenant, 'billing'));
        self::assertTrue(RankComparison::isComparableType($actor->getMorphClass()));
        self::assertFalse(RankComparison::isComparableType('stub-other'));
        self::assertFalse(RankComparison::isComparableType(\stdClass::class));
        self::assertFalse(RankComparison::isComparableType((new Role)->getMorphClass()));

        Relation::morphMap(['ranked-member' => StubIdentity::class]);

        try {
            self::assertTrue(RankComparison::isComparableType('ranked-member'));
        } finally {
            Relation::morphMap([], false);
        }
    }

    /**
     * Rank is a constraint unless `authorization.rank.enabled` turns it off.
     *
     * @return void
     */
    public function testRankIsEnabledUnlessTurnedOff(): void
    {
        self::assertTrue(RankComparison::isEnabled());

        config(['authorization.rank.enabled' => false]);

        self::assertFalse(RankComparison::isEnabled());
    }

    /**
     * Create an identity holding a platform-wide role of each rank given.
     *
     * @param  string  $id
     * @param  int|null  ...$ranks
     * @return \Tests\Feature\Stubs\StubIdentity
     *
     * @throws \Throwable
     */
    private static function holding(string $id, ?int ...$ranks): StubIdentity
    {
        $identity = StubIdentity::create(['id' => $id]);

        foreach ($ranks as $index => $rank) {
            $identity->assignRole(Role::create(['name' => "{$id}-{$index}", 'rank' => $rank]));
        }

        return $identity;
    }

    /**
     * Read the identity again, with nothing loaded.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function fresh(StubIdentity $identity): StubIdentity
    {
        /** @var \Tests\Feature\Stubs\StubIdentity */
        return StubIdentity::query()->whereKey($identity->getKey())->sole();
    }
}
