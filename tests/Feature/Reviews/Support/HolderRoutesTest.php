<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\HolderRoutes;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\ReviewsAccess;
use Tests\TestCase;

/**
 * Feature tests for the holders of a role, a permission or a policy (N93): one
 * row for each route, direct grants, grants of roles below a role, of roles
 * carrying a permission or policy and of the roles below them, every edge live,
 * alternative routes kept, a deny-only policy held, boundaries and resource
 * policies left out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(HolderRoutes::class)]
final class HolderRoutesTest extends TestCase
{
    use ReviewsAccess;

    /**
     * A role is held by its grantees directly, and by the grantees of every
     * role below it, each through the chain up to it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleIsHeldDirectlyAndThroughEveryRoleBelowIt(): void
    {
        $admin  = self::role('admin');
        $editor = self::role('editor', $admin);
        $author = self::role('author', $editor);

        self::grants()->grantRole(self::identity('ann'), $admin);
        self::grants()->grantRole(self::identity('bob'), $editor);
        self::grants()->grantRole(self::identity('cat'), $author);

        self::assertSame([
            'role_grant ann [admin] admin',
            'role_inherited bob [editor>admin] admin',
            'role_inherited cat [author>editor>admin] admin',
        ], self::described(self::trusted(ReviewQuery::holders($admin, ReviewScope::everywhere()))));

        self::assertSame(['role_grant ann [admin] admin'], self::described(self::trusted(ReviewQuery::holders($admin, ReviewScope::everywhere(), true))));
    }

    /**
     * With the hierarchy disabled a role is held only by its own grantees.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithTheHierarchyDisabledARoleIsHeldOnlyDirectly(): void
    {
        config(['authorization.hierarchy.enabled' => false]);

        $admin  = self::role('admin');
        $editor = self::role('editor', $admin);

        $editor->givePermissionTo(self::permission('posts:read'));
        $admin->givePermissionTo(self::permission('posts:edit'));

        self::grants()->grantRole(self::identity('ann'), $admin);
        self::grants()->grantRole(self::identity('bob'), $editor);

        self::assertSame(['role_grant ann [admin] admin'], self::described(self::trusted(ReviewQuery::holders($admin, ReviewScope::everywhere()))));
        self::assertSame(['role_permission ann [admin] posts:edit'], self::described(self::trusted(ReviewQuery::holders(self::named('posts:edit'), ReviewScope::everywhere()))));
        self::assertSame(['role_permission bob [editor] posts:read'], self::described(self::trusted(ReviewQuery::holders(self::named('posts:read'), ReviewScope::everywhere()))));
    }

    /**
     * A permission is held directly, and through every role carrying it, its
     * own or an ancestor's, each route its own row, in the order of the routes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPermissionIsHeldThroughEveryRoleCarryingIt(): void
    {
        $admin      = self::role('admin');
        $editor     = self::role('editor', $admin);
        $permission = self::permission('posts:edit');

        $admin->givePermissionTo($permission);
        $editor->givePermissionTo($permission);

        self::grants()->grantPermission(self::identity('ann'), $permission);
        self::grants()->grantRole(self::identity('bob'), $editor);
        self::grants()->grantRole(self::identity('cat'), $admin);

        $rows = self::described(self::trusted(ReviewQuery::holders($permission, ReviewScope::everywhere())));

        self::assertSame('permission_grant ann posts:edit', $rows[0]);
        self::assertEqualsCanonicalizing(['role_permission bob [editor] posts:edit', 'role_permission bob [editor>admin] posts:edit'], [$rows[1], $rows[2]]);
        self::assertSame('role_permission cat [admin] posts:edit', $rows[3]);
        self::assertCount(4, $rows);

        self::assertSame(['permission_grant ann posts:edit'], self::described(self::trusted(ReviewQuery::holders($permission, ReviewScope::everywhere(), true))));
    }

    /**
     * Alternative routes through different roles are separate rows, each with
     * its own expiry, so the earliest is not when the holding ends.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAlternativeRoutesAreKeptWithTheirOwnExpiry(): void
    {
        $soon       = Carbon::now('UTC')->addDay()->startOfSecond();
        $permission = self::permission('posts:edit');
        $first      = self::role('first');
        $second     = self::role('second');

        self::roles()->grantPermission($first, $permission, $soon);
        self::roles()->grantPermission($second, $permission);

        $holder = self::identity('ann');

        self::grants()->grantRole($holder, $first);
        self::grants()->grantRole($holder, $second);

        $rows = self::trusted(ReviewQuery::holders($permission, ReviewScope::everywhere()))->rows;

        self::assertCount(2, $rows);

        $expiries = \array_map(static fn ($row): ?string => $row->routeExpiresAt()?->toIso8601ZuluString(), $rows);

        self::assertEqualsCanonicalizing([$soon->toIso8601ZuluString(), null], $expiries);
        self::assertNotSame($rows[0]->rowKey, $rows[1]->rowKey);
    }

    /**
     * An expired role permission edge, an expired role grant and an expired
     * policy attachment carry nothing; the exact expiry is already expired.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExpiredEdgesCarryNothing(): void
    {
        $now = new Carbon('2030-01-01 12:00:00', 'UTC');

        Carbon::setTestNow($now);

        try {
            $permission = self::permission('posts:edit');
            $policy     = self::policy('deny-delete');
            $role       = self::role('editor');

            self::roles()->grantPermission($role, $permission, $now->copy()->addMinute());
            self::grants()->attachPolicy($role, $policy, $now->copy()->addMinute());
            self::grants()->grantRole(self::identity('ann'), $role);

            self::assertCount(1, self::trusted(ReviewQuery::holders($permission, ReviewScope::everywhere()))->rows);
            self::assertCount(1, self::trusted(ReviewQuery::holders($policy, ReviewScope::everywhere()))->rows);

            Carbon::setTestNow($now->copy()->addMinute());

            self::assertSame([], self::trusted(ReviewQuery::holders($permission, ReviewScope::everywhere()))->rows);
            self::assertSame([], self::trusted(ReviewQuery::holders($policy, ReviewScope::everywhere()))->rows);
        } finally {
            Carbon::setTestNow();
        }
    }

    /**
     * A policy that only denies is held, directly and through a role and the
     * roles below it; a boundary and a resource policy are not held.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADenyOnlyPolicyIsHeldAndBoundariesAndResourcePoliciesAreNot(): void
    {
        $policy = self::policy('deny-delete');
        $parent = self::role('parent');
        $child  = self::role('child', $parent);

        self::grants()->attachPolicy(self::identity('ann'), $policy);
        self::grants()->attachPolicy($parent, $policy);
        self::grants()->grantRole(self::identity('bob'), $child);

        app(BoundaryService::class)->set(self::identity('cat'), $policy);
        app(ResourcePolicyService::class)->attach($policy, ResourceReference::type('post'));

        self::assertSame([
            'policy_attachment ann deny-delete',
            'role_policy bob [child>parent] deny-delete',
        ], self::described(self::trusted(ReviewQuery::holders($policy, ReviewScope::everywhere()))));
    }

    /**
     * A role's policy reaches a holder of the role only where the role's grant
     * and the attachment hold together: in the same application, and in tenants
     * that meet.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolePolicyNeedsTheGrantAndTheAttachmentToIntersect(): void
    {
        $this->tree();

        $policy = self::policy('deny-delete');
        $role   = self::role('editor');

        self::grants()->attachPolicy($role, $policy, tenant: self::tenant('acct1'), application: 'web');

        self::grants()->grantRole(self::identity('same'), $role, tenant: self::tenant('acct1'), application: 'web');
        self::grants()->grantRole(self::identity('agnostic'), $role, tenant: self::tenant('acct1'));
        self::grants()->grantRole(self::identity('parent'), $role, tenant: self::tenant('org1'));
        self::grants()->grantRole(self::identity('node'), $role, tenant: self::tenant('org1'), includeSubtree: false);
        self::grants()->grantRole(self::identity('child'), $role, tenant: self::tenant('team1'));
        self::grants()->grantRole(self::identity('sibling'), $role, tenant: self::tenant('acct2'));
        self::grants()->grantRole(self::identity('other-app'), $role, tenant: self::tenant('acct1'), application: 'api');
        self::grants()->grantRole(self::identity('platform'), $role);

        $holders = \array_map(static fn ($row): string => $row->subject->id, self::trusted(ReviewQuery::holders($policy, ReviewScope::everywhere()))->rows);

        self::assertEqualsCanonicalizing(['same', 'agnostic', 'parent', 'child', 'platform'], $holders);

        $applying = \array_map(
            static fn ($row): string => $row->subject->id,
            self::trusted(ReviewQuery::holders($policy, ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::named('web'))))->rows,
        );

        self::assertEqualsCanonicalizing(['same', 'agnostic', 'parent', 'platform'], $applying);
        self::assertSame([], self::trusted(ReviewQuery::holders($policy, ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none())))->rows);
    }

    /**
     * Grants that reach a role's policy nowhere are passed over a page at a
     * time, so the limit counts routes, and truncation stays exact.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGrantsReachingNoRouteArePassedOverPageByPage(): void
    {
        $this->tree();

        $policy = self::policy('deny-delete');
        $role   = self::role('editor');

        self::grants()->attachPolicy($role, $policy, tenant: self::tenant('acct1'));

        foreach (['a' => 'acct2', 'b' => 'org2', 'c' => 'acct1', 'd' => 'acct2', 'e' => 'team1'] as $holder => $tenant) {
            self::grants()->grantRole(self::identity($holder), $role, tenant: self::tenant($tenant));
        }

        $query  = ReviewQuery::holders($policy, ReviewScope::everywhere());
        $first  = self::trusted($query->withLimit(1));
        $second = self::trusted($query->withLimit(2));

        self::assertSame([['c'], true], [\array_map(static fn ($row): string => $row->subject->id, $first->rows), $first->isTruncated]);
        self::assertSame([['c', 'e'], false], [\array_map(static fn ($row): string => $row->subject->id, $second->rows), $second->isTruncated]);
    }

    /**
     * A role the reviewed tenant does not see, its owner moved since, ends a
     * chain in a review of what applies there, and holds nothing itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHiddenAncestorEndsTheChain(): void
    {
        $this->tree();

        $hidden = self::role('hidden');
        $child  = self::role('child', $hidden);

        $hidden->givePermissionTo(self::permission('hidden:read'));

        DB::table('roles')->where('id', $hidden->getKey())->update(['tenant_type' => 'tenant', 'tenant_id' => 'org2']);

        self::grants()->grantRole(self::identity('ann'), $child, tenant: self::tenant('acct1'));
        self::grants()->grantRole(self::identity('bob'), $hidden, tenant: self::tenant('acct1'));

        $acct1 = ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none());

        self::assertSame([], self::trusted(ReviewQuery::holders($hidden, $acct1))->rows);
        self::assertSame([], self::trusted(ReviewQuery::holders(self::named('hidden:read'), $acct1))->rows);
        self::assertSame(
            ['role_grant bob [hidden] hidden', 'role_inherited ann [child>hidden] hidden'],
            self::described(self::trusted(ReviewQuery::holders($hidden, ReviewScope::everywhere()))),
        );
        self::assertSame(['role_grant ann [child] child'], self::described(self::trusted(ReviewQuery::holders($child, $acct1))));
    }

    /**
     * A cycle in the stored hierarchy, which the role service never writes,
     * refuses the review, as it refuses a check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACycleRefusesTheReview(): void
    {
        $parent = self::role('parent');
        $child  = self::role('child', $parent);

        try {
            self::roles()->setParent($parent, $child);
            self::fail('The role service wrote a cycle.');
        } catch (RoleHierarchyCycleException) {
            // The role service refuses it.
        }

        DB::table('roles')->where('id', $parent->getKey())->update(['parent_id' => $child->getKey()]);

        self::grants()->grantRole(self::identity('ann'), $child);

        $this->expectException(RoleHierarchyCycleException::class);

        self::trusted(ReviewQuery::holders($parent, ReviewScope::everywhere()));
    }

    /**
     * Two definitions sharing a name under different guards or owners are told
     * apart by key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDefinitionsSharingANameAreToldApart(): void
    {
        $web = self::role('editor');
        $api = new Role;

        $api->forceFill(['name' => 'editor', 'guard' => 'api'])->save();

        $owned = self::role('editor', null, self::tenant('t1'));

        self::grants()->grantRole(self::identity('ann'), $web);
        self::grants()->grantRole(self::identity('bob'), $api);
        self::grants()->grantRole(self::identity('cat'), $owned, tenant: self::tenant('t1'));

        $holders = static fn (Role $role): array => \array_map(
            static fn ($row): string => $row->subject->id,
            self::trusted(ReviewQuery::holders($role, ReviewScope::everywhere()))->rows,
        );

        self::assertSame(['ann'], $holders($web));
        self::assertSame(['bob'], $holders($api));
        self::assertSame(['cat'], $holders($owned));
    }

    /**
     * The holders of a policy through a role are only the grants that meet one
     * of its attachments, however the grants that meet none fall in the
     * review's order, so a small limit still finds the holders and says exactly
     * whether one was left out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicysHoldersAreTheGrantsMeetingAnAttachment(): void
    {
        $this->tree();

        $role   = self::role('carrier');
        $policy = self::policy('deny');

        self::grants()->attachPolicy($role, $policy, tenant: self::tenant('acct1'), application: 'web');

        foreach (['a-sibling' => 'acct2', 'b-team' => 'team1', 'c-other' => 'org2', 'd-account' => 'acct1'] as $holder => $tenant) {
            self::grants()->grantRole(self::identity($holder), $role, tenant: self::tenant($tenant));
        }

        self::grants()->grantRole(self::identity('a-api'), $role, tenant: self::tenant('acct1'), application: 'api');
        self::grants()->grantRole(self::identity('e-parent'), $role, tenant: self::tenant('org1'));
        self::grants()->grantRole(self::identity('a-parent-node'), $role, tenant: self::tenant('org1'), includeSubtree: false);

        $holders = static fn (ReviewQuery $query): array => \array_map(static fn ($row): string => $row->subject->id, self::trusted($query)->rows);

        foreach ([ReviewScope::everywhere(), ReviewScope::rootedWithin(self::tenant('org1'))] as $scope) {
            self::assertEqualsCanonicalizing(['b-team', 'd-account', 'e-parent'], $holders(ReviewQuery::holders($policy, $scope)));

            $first = self::trusted(ReviewQuery::holders($policy, $scope)->withLimit(1));

            self::assertCount(1, $first->rows);
            self::assertTrue($first->isTruncated);
            self::assertFalse(self::trusted(ReviewQuery::holders($policy, $scope)->withLimit(3))->isTruncated);
        }

        $account = static fn (string $application): ReviewScope => ReviewScope::rootedWithin(self::tenant('acct1'), ApplicationSelector::named($application));

        self::assertEqualsCanonicalizing(['b-team', 'd-account'], $holders(ReviewQuery::holders($policy, $account('web'))));
        self::assertSame([], $holders(ReviewQuery::holders($policy, $account('api'))));
    }

    /**
     * A reference whose key no definition could have names no definition, so
     * nothing holds it, on every database, whatever its kind, and it is never
     * compared with a key column: no query is made, so PostgreSQL never refuses
     * a value its `uuid` column cannot hold.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeyNoDefinitionCouldHaveIsHeldByNoOne(): void
    {
        $this->tree();

        $role = self::role('admin');

        self::grants()->grantRole(self::identity('ann'), $role);

        $queries = [];

        DB::listen(static function (QueryExecuted $executed) use (&$queries): void {
            $queries[] = $executed->sql;
        });

        $scopes  = [ReviewScope::everywhere(), ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none()), ReviewScope::rootedWithin(self::tenant('org1'))];
        $keys    = ['not-a-key', '1', '\' or 1=1 --', \str_repeat('a', 191), '00000000-0000-0000-0000-00000000000g'];
        $reviews = [];

        foreach ([$role, self::permission('posts:read'), self::policy('deny')] as $definition) {
            foreach ($keys as $key) {
                foreach ($scopes as $scope) {
                    $reviews[] = ReviewQuery::holders(new Reference(Reference::of($definition)->type, $key), $scope);
                    $reviews[] = ReviewQuery::holders(new Reference(Reference::of($definition)->type, $key), $scope, true);
                }
            }
        }

        foreach ($reviews as $review) {
            $queries = [];

            self::assertSame([], self::trusted($review)->rows);
            self::assertSame([], \array_filter($queries, static fn (string $sql): bool => !\str_contains($sql, 'closure')), \implode("\n", $queries));
        }

        $this->app?->make('events')->forget(QueryExecuted::class);
    }

    /**
     * Each kind of row comes in the order of the kinds: direct grants, then the
     * routes through roles.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDirectGrantsComeBeforeRoutesThroughRoles(): void
    {
        $role = self::role('admin');

        self::grants()->grantRole(self::identity('zed'), $role);
        self::grants()->grantRole(self::identity('amy'), self::role('child', $role));

        $kinds = \array_map(static fn ($row): SourceKind => $row->sourceKind, self::trusted(ReviewQuery::holders($role, ReviewScope::everywhere()))->rows);

        self::assertSame([SourceKind::ROLE_GRANT, SourceKind::ROLE_INHERITED], $kinds);
    }

    /**
     * Return the reference to the permission with the name.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function named(string $name): Reference
    {
        return Reference::of(Permission::query()->withoutGlobalScopes()->where('name', $name)->firstOrFail());
    }
}
