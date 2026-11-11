<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun;
use SineMacula\Laravel\Authorization\Reviews\Support\RoleChains;
use Tests\Concerns\ReviewsAccess;
use Tests\TestCase;

/**
 * Feature tests for the role hierarchy as a review reads it: the roles below a
 * carrier whose chain reaches it, the chain above a held role, each ending at a
 * missing or unseen role, a cycle refused, the hierarchy switched off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RoleChains::class)]
final class RoleChainsTest extends TestCase
{
    use ReviewsAccess;

    /**
     * Below a carrier are the carrier and every role under it, each with its
     * chain up to the carrier; above a held role, its chain to the root.
     *
     * @return void
     */
    public function testChainsRunBelowAndAbove(): void
    {
        [$top, $middle, $bottom, $other] = self::hierarchy();

        $run = ReviewRun::of(ReviewScope::everywhere());

        self::assertSame(self::sorted([
            self::key($top)    => [self::key($top)],
            self::key($middle) => [self::key($middle), self::key($top)],
            self::key($bottom) => [self::key($bottom), self::key($middle), self::key($top)],
        ]), self::sorted(RoleChains::below($run, [self::key($top)])));

        self::assertSame(
            self::sorted([self::key($bottom) => [self::key($bottom), self::key($middle)], self::key($middle) => [self::key($middle)]]),
            self::sorted(RoleChains::below($run, [self::key($middle)])),
        );
        self::assertSame([], RoleChains::below($run, []));
        self::assertSame(
            self::sorted([self::key($bottom) => [self::key($bottom), self::key($middle), self::key($top)], self::key($other) => [self::key($other)]]),
            self::sorted(RoleChains::above($run, [self::key($bottom), self::key($other)])),
        );
        self::assertSame([], RoleChains::above($run, []));
        self::assertSame([], RoleChains::above($run, ['00000000-0000-0000-0000-000000000000']));
    }

    /**
     * With the hierarchy disabled a chain is its role alone, and below a
     * carrier is the carrier alone.
     *
     * @return void
     */
    public function testWithTheHierarchyDisabledAChainIsItsRole(): void
    {
        [$top, , $bottom] = self::hierarchy();

        config(['authorization.hierarchy.enabled' => false]);

        $run = ReviewRun::of(ReviewScope::everywhere());

        self::assertSame([self::key($top) => [self::key($top)]], RoleChains::below($run, [self::key($top)]));
        self::assertSame([self::key($bottom) => [self::key($bottom)]], RoleChains::above($run, [self::key($bottom)]));
    }

    /**
     * In a review of what applies in a tenant, a role the tenant does not see
     * ends a chain, and holds nothing itself.
     *
     * @return void
     */
    public function testAnUnseenRoleEndsTheChain(): void
    {
        $this->tree();

        [$top, $middle, $bottom] = self::hierarchy();

        DB::table('roles')->where('id', $middle->getKey())->update(['tenant_type' => 'tenant', 'tenant_id' => 'org2']);

        $run = ReviewRun::of(ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none()));

        self::assertSame([self::key($top) => [self::key($top)]], RoleChains::below($run, [self::key($top)]));
        self::assertSame([self::key($bottom) => [self::key($bottom)]], RoleChains::above($run, [self::key($bottom), self::key($middle)]));
        self::assertSame([], RoleChains::below($run, [self::key($middle)]));
    }

    /**
     * Return the tenant columns of a role naming half a tenant: a key without a
     * type, and a type without a key.
     *
     * @return iterable<string, array{string|null, string|null}>
     */
    public static function halfTenants(): iterable
    {
        yield 'a key without a type' => [null, 'acct1'];
        yield 'a type without a key' => ['tenant', null];
    }

    /**
     * A role naming half a tenant, a key without a type or a type without a
     * key, is seen in no review of what applies, at the platform or in a
     * tenant, so it ends a chain there, as the tenant scope shows it nowhere; a
     * review of everywhere, or one rooted within a tenant, reads it.
     *
     * @param  string|null  $type
     * @param  string|null  $id
     * @return void
     */
    #[DataProvider('halfTenants')]
    public function testARoleNamingHalfATenantIsSeenInNoReviewOfWhatApplies(?string $type, ?string $id): void
    {
        $this->tree();

        [$top, $middle, $bottom] = self::hierarchy();

        DB::table('roles')->where('id', $middle->getKey())->update(['tenant_type' => $type, 'tenant_id' => $id]);

        $whole = [self::key($bottom) => [self::key($bottom), self::key($middle), self::key($top)]];

        foreach ([ReviewScope::appliesIn(null, ApplicationSelector::none()), ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none())] as $scope) {
            $run = ReviewRun::of($scope);

            self::assertSame([self::key($bottom) => [self::key($bottom)]], RoleChains::above($run, [self::key($bottom)]));
            self::assertSame([], RoleChains::below($run, [self::key($middle)]));
        }

        self::assertSame($whole, RoleChains::above(ReviewRun::of(ReviewScope::everywhere()), [self::key($bottom)]));
        self::assertSame($whole, RoleChains::above(ReviewRun::of(ReviewScope::rootedWithin(self::tenant('acct1'))), [self::key($bottom)]));
    }

    /**
     * A cycle in the stored hierarchy refuses the read, below and above, naming
     * the roles by name.
     *
     * @return void
     */
    public function testACycleIsRefused(): void
    {
        [$top, , $bottom] = self::hierarchy();

        DB::table('roles')->where('id', $top->getKey())->update(['parent_id' => $bottom->getKey()]);

        $run = ReviewRun::of(ReviewScope::everywhere());

        foreach ([static fn (): array => RoleChains::below($run, [self::key($top)]), static fn (): array => RoleChains::above($run, [self::key($bottom)])] as $read) {
            try {
                $read();
                self::fail('A cycle was read.');
            } catch (RoleHierarchyCycleException $exception) {
                self::assertMatchesRegularExpression('/top|middle|bottom/', $exception->getMessage());
            }
        }
    }

    /**
     * A chain's roles are referenced by the role model's morph type.
     *
     * @return void
     */
    public function testAChainsRolesAreReferenced(): void
    {
        $path = RoleChains::path(['a', 'b']);

        self::assertSame([[(new Role)->getMorphClass(), 'a'], [(new Role)->getMorphClass(), 'b']], [[$path[0]->type, $path[0]->id], [$path[1]->type, $path[1]->id]]);
        self::assertSame([], RoleChains::path([]));
    }

    /**
     * Return a chain of three roles and one apart.
     *
     * @return list<\SineMacula\Laravel\Authorization\Models\Role>
     */
    private static function hierarchy(): array
    {
        $top    = self::role('top');
        $middle = self::role('middle', $top);
        $bottom = self::role('bottom', $middle);

        return [$top, $middle, $bottom, self::role('other')];
    }

    /**
     * Return the role's key.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return string
     */
    private static function key(Role $role): string
    {
        /** @var string */
        return $role->getKey();
    }

    /**
     * Return the chains sorted by role key.
     *
     * @param  array<string, list<string>>  $chains
     * @return array<string, list<string>>
     */
    private static function sorted(array $chains): array
    {
        \ksort($chains, \SORT_STRING);

        return $chains;
    }
}
