<?php

declare(strict_types = 1);

namespace Tests\Feature\Reviews\Support;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRow;
use SineMacula\Laravel\Authorization\Reviews\Support\GrantRows;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ReviewsAccess;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\CountingTenantTree;
use Tests\TestCase;

/**
 * Feature tests for one run of an access review: its scope's selection of
 * grants by applicability, by root and everywhere, with the application
 * selected, the live rule at its frozen instant, the definitions a tenant sees,
 * and where a role's grant and a policy attachment hold together.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ReviewRun::class)]
final class ReviewRunTest extends TestCase
{
    use ReviewsAccess;

    /**
     * Applicability selects what a check in the tenant reads: the platform's,
     * the tenant's own, and an ancestor's reaching below, never a child's, a
     * sibling's or an ancestor's node alone; at the platform, the platform's
     * alone. That runs the other way to containment, which selects the tenant's
     * own and those below it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testApplicabilityIsNotContainment(): void
    {
        $this->seedGrants();

        self::assertEqualsCanonicalizing(['platform', 'org1', 'acct1'], self::selected(ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none())));
        self::assertEqualsCanonicalizing(['platform', 'web', 'api'], self::selected(ReviewScope::appliesIn(null, ApplicationSelector::any())));
        self::assertEqualsCanonicalizing(['org1-node', 'org1', 'acct1', 'team1', 'acct2'], self::selected(ReviewScope::rootedWithin(self::tenant('org1'))));
        self::assertEqualsCanonicalizing(['acct1', 'team1'], self::selected(ReviewScope::rootedWithin(self::tenant('acct1'))));
        self::assertEqualsCanonicalizing(['platform', 'org1-node', 'org1', 'acct1', 'team1', 'acct2', 'org2', 'web', 'api'], self::selected(ReviewScope::everywhere()));
    }

    /**
     * The application selected keeps the grants for every application, those
     * and a named one's, or all of them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationIsSelectedExplicitly(): void
    {
        $this->seedGrants();

        self::assertEqualsCanonicalizing(['platform'], self::selected(ReviewScope::appliesIn(null, ApplicationSelector::none())));
        self::assertEqualsCanonicalizing(['platform', 'web'], self::selected(ReviewScope::appliesIn(null, ApplicationSelector::named('web'))));
        self::assertEqualsCanonicalizing(['platform', 'web', 'api'], self::selected(ReviewScope::appliesIn(null, ApplicationSelector::any())));
        self::assertEqualsCanonicalizing(
            ['platform', 'org1-node', 'org1', 'acct1', 'team1', 'acct2', 'org2', 'api'],
            self::selected(ReviewScope::everywhere(ApplicationSelector::named('api'))),
        );
    }

    /**
     * A row is live until its expiry, at the run's frozen instant, and expired
     * at the instant itself.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARowIsLiveUntilItsExpiryAtTheRunsInstant(): void
    {
        $now = new Carbon('2030-01-01 00:00:00', 'UTC');

        Carbon::setTestNow($now);

        try {
            $role = self::role('role');

            self::grants()->grantRole(new Reference('u', 'now'), $role, $now->copy()->addSecond());
            self::grants()->grantRole(new Reference('u', 'later'), $role, $now->copy()->addSeconds(2));
            self::grants()->grantRole(new Reference('u', 'never'), $role);

            $run = ReviewRun::of(ReviewScope::everywhere());

            Carbon::setTestNow($now->copy()->addSecond());

            self::assertSame($now->toIso8601ZuluString(), $run->now->toIso8601ZuluString());
            self::assertSame(['later', 'never', 'now'], self::live($run));
            self::assertSame(['later', 'never'], self::live(ReviewRun::of(ReviewScope::everywhere())));
        } finally {
            Carbon::setTestNow();
        }
    }

    /**
     * In a review of what applies in a tenant, a role or permission counts only
     * when the tenant sees it; a policy always, and every definition in any
     * other review.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantSeesItsChainsDefinitions(): void
    {
        $this->tree();

        $own    = self::role('own', null, self::tenant('acct1'));
        $parent = self::role('parent', null, self::tenant('org1'));
        $child  = self::role('child', null, self::tenant('team1'));
        $shared = self::role('shared');

        $run   = ReviewRun::of(ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none()));
        $other = ReviewRun::of(ReviewScope::rootedWithin(self::tenant('acct1')));

        self::assertTrue($run->isApplicability());
        self::assertFalse($other->isApplicability());

        foreach ([[$own, true], [$parent, true], [$shared, true], [$child, false]] as [$role, $isSeen]) {
            self::assertSame($isSeen, $run->seesDefinition(GrantTarget::ROLE, Reference::of($role)->id));
            self::assertSame($isSeen, $run->sees(Reference::tenantOf($role)));
            self::assertTrue($other->seesDefinition(GrantTarget::ROLE, Reference::of($role)->id));
            self::assertTrue($other->sees(Reference::tenantOf($role)));
        }

        self::assertFalse($run->seesDefinition(GrantTarget::ROLE, (string) Str::uuid()));
        self::assertTrue($run->seesDefinition(GrantTarget::POLICY, (string) Str::uuid()));
        self::assertFalse($run->seesDefinition(GrantTarget::PERMISSION, Reference::of(self::permission('child:read', self::tenant('team1')))->id));
        self::assertTrue($run->seesDefinition(GrantTarget::PERMISSION, Reference::of(self::permission('own:read', self::tenant('acct1')))->id));

        $table = GrantTarget::ROLE->table();

        foreach ([$own, $child] as $role) {
            self::grants()->grantRole(self::identity('holder-' . $role->name), $role, tenant: self::tenant('team1'));
        }

        $visible = static fn (ReviewRun $review): array => \array_map(
            static fn (GrantRow $row): string => $row->grantee->id,
            GrantRows::all($review->visible(GrantRows::of(GrantTarget::ROLE), GrantTarget::ROLE, $table . '.role_id'), 'role'),
        );

        self::assertSame(['holder-own'], $visible($run));
        self::assertEqualsCanonicalizing(['holder-own', 'holder-child'], $visible($other));

        $policyTable = GrantTarget::POLICY->table();

        self::grants()->attachPolicy(self::identity('attached'), self::policy('deny'));

        self::assertCount(1, GrantRows::all($run->visible(GrantRows::of(GrantTarget::POLICY), GrantTarget::POLICY, $policyTable . '.policy_id'), 'policy'));
    }

    /**
     * A review of what applies in a tenant keeps a policy attachment to a role
     * only when the tenant sees the role, matching the role's key as text on
     * every database; any other review keeps every attachment.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyAttachmentToARoleNeedsTheRoleSeen(): void
    {
        $this->tree();

        $table = GrantTarget::POLICY->table();
        $own   = self::role('own', null, self::tenant('acct1'));
        $child = self::role('child', null, self::tenant('team1'));

        self::grants()->attachPolicy($own, self::policy('deny-own'));
        self::grants()->attachPolicy($child, self::policy('deny-child'));

        $attached = static fn (ReviewRun $review): array => \array_map(
            static fn (GrantRow $row): string => $row->grantee->id,
            GrantRows::all($review->visibleRoles(GrantRows::of(GrantTarget::POLICY), $table), 'policy'),
        );

        self::assertSame([Reference::of($own)->id], $attached(ReviewRun::of(ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none()))));
        self::assertSame([], $attached(ReviewRun::of(ReviewScope::appliesIn(null, ApplicationSelector::none()))));
        self::assertEqualsCanonicalizing([Reference::of($own)->id, Reference::of($child)->id], $attached(ReviewRun::of(ReviewScope::rootedWithin(self::tenant('acct1')))));
        self::assertEqualsCanonicalizing([Reference::of($own)->id, Reference::of($child)->id], $attached(ReviewRun::of(ReviewScope::everywhere())));
    }

    /**
     * A definition table is selected by its owner: those the tenant sees, those
     * owned within the tenant, or every one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDefinitionsAreSelectedByTheirOwner(): void
    {
        $this->tree();

        $tenants = ['platform' => null, 'org1' => self::tenant('org1'), 'acct1' => self::tenant('acct1'), 'team1' => self::tenant('team1'), 'acct2' => self::tenant('acct2')];

        foreach ($tenants as $name => $owner) {
            self::role($name, null, $owner);
        }

        $owned = static fn (ReviewScope $scope): array => DB::table('roles')->tap(static fn ($query) => ReviewRun::of($scope)->owned($query, 'roles'))->pluck('name')->all();

        self::assertEqualsCanonicalizing(['platform', 'org1', 'acct1'], $owned(ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none())));
        self::assertEqualsCanonicalizing(['acct1', 'team1'], $owned(ReviewScope::rootedWithin(self::tenant('acct1'))));
        self::assertEqualsCanonicalizing(['platform', 'org1', 'acct1', 'team1', 'acct2'], $owned(ReviewScope::everywhere()));
    }

    /**
     * A role's grant and a policy attachment hold together where their
     * applications meet, and, outside a review of what applies in a tenant,
     * where their tenants meet: either is the platform's, both one tenant's, or
     * one reaches below the other's tenant; the tree is asked once for each
     * pair in the run.
     *
     * @return void
     */
    public function testAGrantAndAnAttachmentIntersectWhereTheyHoldTogether(): void
    {
        $this->tree();

        $counting = new CountingTenantTree(new ClosureTenantTree);

        $this->app?->instance(TenantTree::class, $counting);

        $run   = ReviewRun::of(ReviewScope::everywhere());
        $scope = static fn (?string $tenant, ?string $application = null, bool $isSubtree = true): GrantScope => new GrantScope(
            $tenant === null ? null : self::tenant($tenant),
            $application,
            $isSubtree,
        );

        self::assertTrue($run->intersects($scope(null), $scope('acct1')));
        self::assertTrue($run->intersects($scope('acct1', null, false), $scope(null)));
        self::assertTrue($run->intersects($scope('acct1', null, false), $scope('acct1', null, false)));
        self::assertTrue($run->intersects($scope('org1'), $scope('team1', null, false)));
        self::assertTrue($run->intersects($scope('team1', null, false), $scope('org1')));
        self::assertFalse($run->intersects($scope('org1', null, false), $scope('team1')));
        self::assertFalse($run->intersects($scope('team1'), $scope('org1', null, false)));
        self::assertFalse($run->intersects($scope('acct1'), $scope('acct2')));
        self::assertFalse($run->intersects($scope('org1'), $scope('org2')));

        self::assertTrue($run->intersects($scope(null, 'web'), $scope(null)));
        self::assertTrue($run->intersects($scope(null), $scope(null, 'web')));
        self::assertTrue($run->intersects($scope(null, 'web'), $scope(null, 'web')));
        self::assertFalse($run->intersects($scope(null, 'web'), $scope(null, 'api')));

        $asked = $counting->withinAsked;

        $run->intersects($scope('team1'), $scope('org1', null, false));

        self::assertSame($asked, $counting->withinAsked);

        $applying = ReviewRun::of(ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::any()));

        self::assertTrue($applying->intersects($scope('org1'), $scope('acct1', null, false)));
        self::assertFalse($applying->intersects($scope('org1', 'web'), $scope('acct1', 'api')));
    }

    /**
     * A grant naming half a tenant is selected exactly where a check reads it:
     * a key without a type at the platform, so wherever what applies is read,
     * and a type without a key nowhere; a review of everywhere selects a type
     * without a key too, and a review rooted within a tenant selects neither,
     * since neither can be shown to lie within it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARowNamingHalfATenantIsSelectedWhereACheckReadsIt(): void
    {
        $this->seedGrants();

        $role  = self::role('halved');
        $table = GrantTarget::ROLE->table();

        self::grants()->grantRole(new Reference('u', 'no-key'), $role, tenant: self::tenant('acct1'));
        self::grants()->grantRole(new Reference('u', 'no-type'), $role, tenant: self::tenant('acct1'));

        DB::table($table)->where('authorizable_id', 'no-key')->update(['tenant_id' => null]);
        DB::table($table)->where('authorizable_id', 'no-type')->update(['tenant_type' => null]);

        $halves = static fn (ReviewScope $scope): array => \array_values(\array_intersect(self::selected($scope), ['no-key', 'no-type']));

        self::assertEqualsCanonicalizing(['no-key', 'no-type'], $halves(ReviewScope::everywhere()));
        self::assertSame(['no-type'], $halves(ReviewScope::appliesIn(null, ApplicationSelector::any())));
        self::assertSame(['no-type'], $halves(ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::none())));
        self::assertSame([], $halves(ReviewScope::rootedWithin(self::tenant('org1'))));
        self::assertSame([], $halves(ReviewScope::rootedWithin(self::tenant('org2'))));
        self::assertEqualsCanonicalizing(['acct1', 'team1'], self::selected(ReviewScope::rootedWithin(self::tenant('acct1'))));
    }

    /**
     * A role grant query is limited in SQL to the grants that meet an
     * attachment exactly where the run weighs them as meeting: the same
     * applications, and outside a review of what applies in a tenant, the same
     * tenants.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantMeetsAnAttachmentInSqlAsItDoesInPhp(): void
    {
        $this->seedGrants();

        $table       = GrantTarget::ROLE->table();
        $attachments = [
            new GrantScope(null, null, true),
            new GrantScope(self::tenant('acct1'), null, true),
            new GrantScope(self::tenant('acct1'), 'web', false),
            new GrantScope(self::tenant('team1'), null, false),
            new GrantScope(self::tenant('org2'), 'api', true),
        ];

        foreach ([ReviewScope::everywhere(), ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::any())] as $scope) {
            $run    = ReviewRun::of($scope);
            $grants = GrantRows::all($run->constrain(GrantRows::of(GrantTarget::ROLE), $table), 'role');

            foreach ($attachments as $attachment) {
                $expected = \array_values(\array_map(
                    static fn (GrantRow $grant): string => $grant->grantee->id,
                    \array_filter($grants, static fn (GrantRow $grant): bool => $grant->scope !== null && $run->intersects($grant->scope, $attachment)),
                ));

                $read = GrantRows::all($run->meeting($run->constrain(GrantRows::of(GrantTarget::ROLE), $table), $table, $attachment), 'role');

                self::assertEqualsCanonicalizing($expected, \array_map(static fn (GrantRow $grant): string => $grant->grantee->id, $read));
            }
        }
    }

    /**
     * Once the run settles the grants and attachments it read, weighing them
     * asks the tree nothing more; a review of what applies in a tenant settles
     * nothing, and needs nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSettledGrantsAndAttachmentsAskTheTreeNothing(): void
    {
        $this->tree();

        $counting = new CountingTenantTree(new ClosureTenantTree);

        $this->app?->instance(TenantTree::class, $counting);

        $grant = static fn (string $tenant, bool $isSubtree): GrantRow => GrantRow::from(
            (object) ['target_id' => 'r', 'grantee_type' => 'u', 'grantee_id' => $tenant, 'tenant_type' => 'tenant', 'tenant_id' => $tenant, 'include_subtree' => $isSubtree],
            'role',
        );
        $grants   = [$grant('team1', false), $grant('acct2', false), $grant('org1', true), $grant('org2', true)];
        $attached = GrantRow::from(
            (object) ['target_id' => 'p', 'grantee_type' => 'role', 'grantee_id' => 'r', 'tenant_type' => 'tenant', 'tenant_id' => 'acct1', 'include_subtree' => true],
            'policy',
        );
        $attachments = ['r' => [$attached]];
        $run         = ReviewRun::of(ReviewScope::everywhere());

        $run->settle($grants, $attachments);

        $asked = [$counting->withinAsked, $counting->ancestorsRead];
        $meets = \array_map(static fn (GrantRow $one): bool => $one->scope !== null && $attached->scope !== null && $run->intersects($one->scope, $attached->scope), $grants);

        self::assertSame([true, false, true, false], $meets);
        self::assertSame($asked, [$counting->withinAsked, $counting->ancestorsRead]);

        $applying = ReviewRun::of(ReviewScope::appliesIn(self::tenant('acct1'), ApplicationSelector::any()));
        $before   = [$counting->withinAsked, $counting->ancestorsRead];

        $applying->settle($grants, $attachments);

        self::assertSame($before, [$counting->withinAsked, $counting->ancestorsRead]);
    }

    /**
     * Seed the tree, and grant one role in each scope: the platform, a node of
     * the first organisation, its subtree, each account, the team, the second
     * organisation, and the platform for each of two applications.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function seedGrants(): void
    {
        $this->tree();

        $role = self::role('reviewed');

        self::grants()->grantRole(new Reference('u', 'platform'), $role);
        self::grants()->grantRole(new Reference('u', 'org1-node'), $role, tenant: self::tenant('org1'), includeSubtree: false);
        self::grants()->grantRole(new Reference('u', 'web'), $role, application: 'web');
        self::grants()->grantRole(new Reference('u', 'api'), $role, application: 'api');

        foreach (['org1', 'acct1', 'team1', 'acct2', 'org2'] as $tenant) {
            self::grants()->grantRole(new Reference('u', $tenant), $role, tenant: self::tenant($tenant));
        }
    }

    /**
     * Return the grantees of the role grants the scope selects.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @return list<string>
     */
    private static function selected(ReviewScope $scope): array
    {
        $table = GrantTarget::ROLE->table();

        return \array_map(
            static fn (GrantRow $row): string => $row->grantee->id,
            GrantRows::all(ReviewRun::of($scope)->constrain(GrantRows::of(GrantTarget::ROLE), $table), 'role'),
        );
    }

    /**
     * Return the grantees of the role grants live at the run's instant.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @return list<string>
     */
    private static function live(ReviewRun $run): array
    {
        $table = GrantTarget::ROLE->table();

        return \array_map(
            static fn (GrantRow $row): string => $row->grantee->id,
            GrantRows::all(GrantRows::ordered($run->live(GrantRows::of(GrantTarget::ROLE), $table), $table, 'role_id'), 'role'),
        );
    }
}
