<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Resolvers\NullTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Traits\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use SineMacula\Laravel\Authorization\Traits\ManagesPermissions;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for role rank / seniority.
 *
 * Validates the rank column, the `isRanked()`, `outranks()`, and
 * `outranksOrEquals()` helpers on the Role model, and the
 * `canActOn()` advisory helper on identities using the `HasRoles`
 * trait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Role::class)]
#[CoversClass(RoleObserver::class)]
#[CoversClass(TenantScope::class)]
#[CoversClass(NullTenantResolver::class)]
#[CoversClass(ResolutionCacheContext::class)]
#[CoversClass(InvalidTenantException::class)]
#[CoversClass(InvalidTenantColumnsException::class)]
#[CoversClass(GuardScopedLookup::class)]
#[CoversTrait(HasRoleHierarchy::class)]
#[CoversTrait(ManagesPermissions::class)]
#[CoversTrait(HasRoles::class)]
final class RoleRankTest extends TestCase
{
    /**
     * A rank-0 principal can act on a rank-5 principal.
     *
     * @return void
     */
    public function testRank0CanActOnRank5(): void
    {
        $seniorRole = $this->makeRole('super-admin', rank: 0);
        $juniorRole = $this->makeRole('editor', rank: 5);

        $actor  = $this->makeIdentity('actor-1');
        $target = $this->makeIdentity('target-1');

        $actor->assignRole($seniorRole);
        $target->assignRole($juniorRole);

        /** @var \Tests\Feature\Stubs\StubIdentity $freshActor */
        $freshActor = $actor->fresh();
        /** @var \Tests\Feature\Stubs\StubIdentity $freshTarget */
        $freshTarget = $target->fresh();

        self::assertTrue($freshActor->canActOn($freshTarget));
    }

    /**
     * A rank-5 principal cannot act on a rank-0 principal.
     *
     * @return void
     */
    public function testRank5CannotActOnRank0(): void
    {
        $seniorRole = $this->makeRole('super-admin', rank: 0);
        $juniorRole = $this->makeRole('editor', rank: 5);

        $actor  = $this->makeIdentity('actor-2');
        $target = $this->makeIdentity('target-2');

        $actor->assignRole($juniorRole);
        $target->assignRole($seniorRole);

        /** @var \Tests\Feature\Stubs\StubIdentity $freshActor */
        $freshActor = $actor->fresh();
        /** @var \Tests\Feature\Stubs\StubIdentity $freshTarget */
        $freshTarget = $target->fresh();

        self::assertFalse($freshActor->canActOn($freshTarget));
    }

    /**
     * Equal-rank principals cannot act on each other (strict senior).
     *
     * @return void
     */
    public function testEqualRankCannotActOnEachOther(): void
    {
        $roleA = $this->makeRole('admin-a', rank: 3);
        $roleB = $this->makeRole('admin-b', rank: 3);

        $alice = $this->makeIdentity('alice');
        $bob   = $this->makeIdentity('bob');

        $alice->assignRole($roleA);
        $bob->assignRole($roleB);

        /** @var \Tests\Feature\Stubs\StubIdentity $freshAlice */
        $freshAlice = $alice->fresh();
        /** @var \Tests\Feature\Stubs\StubIdentity $freshBob */
        $freshBob = $bob->fresh();

        self::assertFalse($freshAlice->canActOn($freshBob));
        self::assertFalse($freshBob->canActOn($freshAlice));
    }

    /**
     * An unranked actor cannot act on a ranked target.
     *
     * @return void
     */
    public function testUnrankedActorCannotActOnRankedTarget(): void
    {
        $unrankedRole = $this->makeRole('guest', rank: null);
        $rankedRole   = $this->makeRole('editor', rank: 5);

        $actor  = $this->makeIdentity('actor-3');
        $target = $this->makeIdentity('target-3');

        $actor->assignRole($unrankedRole);
        $target->assignRole($rankedRole);

        /** @var \Tests\Feature\Stubs\StubIdentity $freshActor */
        $freshActor = $actor->fresh();
        /** @var \Tests\Feature\Stubs\StubIdentity $freshTarget */
        $freshTarget = $target->fresh();

        self::assertFalse($freshActor->canActOn($freshTarget));
    }

    /**
     * A ranked actor can act on an unranked target.
     *
     * @return void
     */
    public function testRankedActorCanActOnUnrankedTarget(): void
    {
        $rankedRole   = $this->makeRole('admin', rank: 2);
        $unrankedRole = $this->makeRole('guest', rank: null);

        $actor  = $this->makeIdentity('actor-4');
        $target = $this->makeIdentity('target-4');

        $actor->assignRole($rankedRole);
        $target->assignRole($unrankedRole);

        /** @var \Tests\Feature\Stubs\StubIdentity $freshActor */
        $freshActor = $actor->fresh();
        /** @var \Tests\Feature\Stubs\StubIdentity $freshTarget */
        $freshTarget = $target->fresh();

        self::assertTrue($freshActor->canActOn($freshTarget));
    }

    /**
     * Both unranked returns false (no rank authority either way).
     *
     * @return void
     */
    public function testBothUnrankedReturnsFalse(): void
    {
        $roleA = $this->makeRole('guest-a', rank: null);
        $roleB = $this->makeRole('guest-b', rank: null);

        $actor  = $this->makeIdentity('actor-5');
        $target = $this->makeIdentity('target-5');

        $actor->assignRole($roleA);
        $target->assignRole($roleB);

        /** @var \Tests\Feature\Stubs\StubIdentity $freshActor */
        $freshActor = $actor->fresh();
        /** @var \Tests\Feature\Stubs\StubIdentity $freshTarget */
        $freshTarget = $target->fresh();

        self::assertFalse($freshActor->canActOn($freshTarget));
    }

    /**
     * `outranks()` and `outranksOrEquals()` on the Role model.
     *
     * @return void
     */
    public function testOutranksAndOutranksOrEquals(): void
    {
        $senior   = $this->makeRole('senior', rank: 0);
        $junior   = $this->makeRole('junior', rank: 5);
        $peer     = $this->makeRole('peer', rank: 0);
        $unranked = $this->makeRole('unranked', rank: null);

        // outranks
        self::assertTrue($senior->outranks($junior));
        self::assertFalse($junior->outranks($senior));
        self::assertFalse($senior->outranks($peer));
        self::assertFalse($senior->outranks($unranked));
        self::assertFalse($unranked->outranks($senior));

        // outranksOrEquals
        self::assertTrue($senior->outranksOrEquals($junior));
        self::assertFalse($junior->outranksOrEquals($senior));
        self::assertTrue($senior->outranksOrEquals($peer));
        self::assertFalse($senior->outranksOrEquals($unranked));
        self::assertFalse($unranked->outranksOrEquals($senior));
    }

    /**
     * `canActOn()` returns true for everything when `rank.enabled`
     * is false.
     *
     * @return void
     */
    public function testCanActOnReturnsTrueWhenRankDisabled(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.rank.enabled', false);

        $seniorRole = $this->makeRole('super-admin', rank: 0);
        $juniorRole = $this->makeRole('editor', rank: 5);

        $actor  = $this->makeIdentity('actor-6');
        $target = $this->makeIdentity('target-6');

        $actor->assignRole($juniorRole);
        $target->assignRole($seniorRole);

        // Junior acting on senior — normally blocked, but rank is disabled.
        /** @var \Tests\Feature\Stubs\StubIdentity $freshActor */
        $freshActor = $actor->fresh();
        /** @var \Tests\Feature\Stubs\StubIdentity $freshTarget */
        $freshTarget = $target->fresh();

        self::assertTrue($freshActor->canActOn($freshTarget));
    }

    /**
     * Multiple roles — highest rank (lowest number) wins.
     *
     * @return void
     */
    public function testMultipleRolesHighestRankWins(): void
    {
        $lowRole  = $this->makeRole('viewer', rank: 10);
        $highRole = $this->makeRole('super-admin', rank: 1);
        $midRole  = $this->makeRole('editor', rank: 5);

        $actor  = $this->makeIdentity('actor-7');
        $target = $this->makeIdentity('target-7');

        // Actor gets rank 10 and rank 1 — best is 1.
        $actor->assignRole($lowRole);
        $actor->assignRole($highRole);

        // Target gets rank 5 — best is 5.
        $target->assignRole($midRole);

        // Actor's best (1) < target's best (5) — can act.
        /** @var \Tests\Feature\Stubs\StubIdentity $freshActor */
        $freshActor = $actor->fresh();
        /** @var \Tests\Feature\Stubs\StubIdentity $freshTarget */
        $freshTarget = $target->fresh();

        self::assertTrue($freshActor->canActOn($freshTarget));
    }

    /**
     * `isRanked()` returns true for ranked roles and false for
     * unranked roles.
     *
     * @return void
     */
    public function testIsRankedHelper(): void
    {
        $ranked   = $this->makeRole('admin', rank: 0);
        $unranked = $this->makeRole('guest', rank: null);

        self::assertTrue($ranked->isRanked());
        self::assertFalse($unranked->isRanked());
    }

    /**
     * `canActOn()` returns false when the target does not implement
     * `SupportsRoles`.
     *
     * @return void
     */
    public function testCanActOnReturnsFalseForNonSupportsRolesTarget(): void
    {
        $rankedRole = $this->makeRole('admin', rank: 0);
        $actor      = $this->makeIdentity('actor-8');
        $actor->assignRole($rankedRole);

        $plainObject = new \stdClass;

        /** @var \Tests\Feature\Stubs\StubIdentity $freshActor */
        $freshActor = $actor->fresh();

        self::assertFalse($freshActor->canActOn($plainObject));
    }

    /**
     * Build a web-guarded role with the given name and optional rank.
     *
     * @param  string  $name
     * @param  int|null  $rank
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private function makeRole(string $name, ?int $rank = null): Role
    {
        return Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => $name,
            'guard_name' => 'web',
            'rank'       => $rank,
        ]);
    }

    /**
     * Build a stub identity with the given name.
     *
     * @param  string  $name
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function makeIdentity(string $name): StubIdentity
    {
        return StubIdentity::create([
            'id'   => (string) Str::uuid(),
            'name' => $name,
        ]);
    }
}
