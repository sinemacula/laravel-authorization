<?php

declare(strict_types = 1);

namespace Tests\Feature\Exclusions\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Exclusions\ConflictReport;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionConflict;
use SineMacula\Laravel\Authorization\Exclusions\Support\ConflictReader;
use SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionWrite;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\RecordsRowLocks;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `ConflictReader`: who holds both roles of a pair where
 * their reach overlaps, by tenant, subtree, platform and application, through
 * parent roles, and through a principal's identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ConflictReader::class)]
final class ConflictReaderTest extends TestCase
{
    use ComparesReferences, RecordsRowLocks;

    /** @var string The type of the stub tenants. */
    private const string TENANT = 'stub_tenant';

    /**
     * Clear the morph map before the application boots, then put the stub
     * tenants in a tree: `child` and `grandchild` below `parent`, `sibling`
     * beside `child`, and `other` at the top on its own.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        Relation::morphMap([], false);

        parent::setUp();

        $tree = (new StubTenantTree)
            ->put(self::tenant('parent'), null)
            ->put(self::tenant('child'), self::tenant('parent'))
            ->put(self::tenant('grandchild'), self::tenant('child'))
            ->put(self::tenant('sibling'), self::tenant('parent'))
            ->put(self::tenant('other'), null);

        $this->app?->instance(TenantTree::class, $tree);
    }

    /**
     * Clear the morph map.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * Two grants in the same tenant overlap, each a direct route naming its
     * grantee, its role and its scope; one grant at the platform overlaps one
     * in any tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testHoldingsInOneTenantOrAtThePlatformConflict(): void
    {
        [$clerk, $auditor] = self::roles();

        $user  = StubIdentity::query()->create(['id' => 'user']);
        $other = StubIdentity::query()->create(['id' => 'other']);

        self::grants()->grantRole($user, $clerk, tenant: self::tenant('child'));
        self::grants()->grantRole($user, $auditor, tenant: self::tenant('child'), includeSubtree: false);
        self::grants()->grantRole($other, $clerk);
        self::grants()->grantRole($other, $auditor, tenant: self::tenant('other'), includeSubtree: false);
        self::grants()->grantRole(StubIdentity::query()->create(['id' => 'lonely']), $clerk, tenant: self::tenant('sibling'));

        $tree   = $this->tree();
        $report = self::report($clerk, $auditor);

        self::assertSame(0, $tree->reads);

        self::assertCount(2, $report->conflicts);
        self::assertSame(['other', 'user'], \array_map(static fn (Reference $holder): string => $holder->id, $report->holders()));

        $conflict = self::conflictOf($report, $user);

        self::assertNull($conflict->identity);
        self::assertTrue(self::refersTo($conflict->first->grantee, $user));
        self::assertTrue(self::refersTo($conflict->first->role, $clerk));
        self::assertTrue($conflict->first->isDirect());
        self::assertEquals(self::tenant('child'), $conflict->first->scope->tenant);
        self::assertTrue($conflict->first->scope->includeSubtree);
        self::assertTrue(self::refersTo($conflict->second->role, $auditor));
        self::assertFalse($conflict->second->scope->includeSubtree);
        self::assertNull(self::conflictOf($report, $other)->first->scope->tenant);
        self::assertTrue($report->isComplete);
    }

    /**
     * Given a write, each report keeps only the conflicts the write creates,
     * those a route of its own takes part in, read as the write leaves the
     * holdings, and leaves out any already stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWritesReportKeepsOnlyTheConflictsItCreates(): void
    {
        [$clerk, $auditor] = self::roles();

        $user  = StubIdentity::query()->create(['id' => 'user']);
        $other = StubIdentity::query()->create(['id' => 'other']);

        self::grants()->grantRole($user, $clerk);
        self::grants()->grantRole($user, $auditor);
        self::grants()->grantRole($other, $clerk);

        $reader = new ConflictReader(new ListedIdentityDirectory);
        $pair   = [[Reference::of($clerk), Reference::of($auditor)]];
        $report = $reader->read($pair, write: ExclusionWrite::proposed(Reference::of($other), $auditor->id, new GrantScope(self::tenant('child'))))[0];

        self::assertSame(['other'], self::holderKeys($report));
        self::assertNotSame([], $reader->read($pair, write: ExclusionWrite::proposed(Reference::of($user), $auditor->id, new GrantScope(self::tenant('other'))))[0]->conflicts);
        self::assertTrue($reader->read($pair, write: ExclusionWrite::granted(Reference::of($other), [[$clerk->id, GrantScope::platform()]]))[0]->isEmpty());
        self::assertCount(1, $reader->read($pair)[0]->conflicts);
    }

    /**
     * A grant reaching below a tenant overlaps one in a tenant below it, on
     * either side of the pair and however deep, but one limited to its own
     * tenant never does, and grants in disjoint tenants never overlap.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSubtreesOverlapButDisjointTenantsAndNodesBelowAGrantDoNot(): void
    {
        [$clerk, $auditor] = self::roles();

        $holders = [
            'down'    => [['parent', true], ['grandchild', false]],
            'up'      => [['child', false], ['parent', true]],
            'node'    => [['parent', false], ['child', true]],
            'nodeUp'  => [['child', true], ['parent', false]],
            'sibling' => [['child', true], ['sibling', true]],
            'apart'   => [['parent', true], ['other', true]],
        ];

        foreach ($holders as $id => [[$first, $firstBelow], [$second, $secondBelow]]) {
            $holder = StubIdentity::query()->create(['id' => $id]);

            self::grants()->grantRole($holder, $clerk, tenant: self::tenant($first), includeSubtree: $firstBelow);
            self::grants()->grantRole($holder, $auditor, tenant: self::tenant($second), includeSubtree: $secondBelow);
        }

        self::assertSame(['down', 'up'], self::holderKeys(self::report($clerk, $auditor)));
        self::assertSame(0, $this->tree()->reads);
    }

    /**
     * Whether a tenant lies within another is settled in one query for every
     * holder, and only where a route reaches below its tenant: routes in two
     * tenants, neither reaching below, cost no more than routes in one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTreeIsReadOnlyWhereARouteReachesBelow(): void
    {
        [$clerk, $auditor] = self::roles();

        $holder = StubIdentity::query()->create(['id' => 'holder']);

        self::grants()->grantRole($holder, $clerk, tenant: self::tenant('child'), includeSubtree: false);
        self::grants()->grantRole($holder, $auditor, tenant: self::tenant('child'), includeSubtree: false);

        $same = self::queriesOf(static fn (): ConflictReport => self::report($clerk, $auditor));

        self::grants()->revokeRole($holder, $auditor, tenant: self::tenant('child'));
        self::grants()->grantRole($holder, $auditor, tenant: self::tenant('parent'), includeSubtree: false);

        self::assertSame($same, self::queriesOf(static fn (): ConflictReport => self::report($clerk, $auditor)));

        foreach (['one' => ['grandchild', 'parent'], 'two' => ['sibling', 'parent'], 'three' => ['other', 'parent']] as $id => [$first, $second]) {
            $below = StubIdentity::query()->create(['id' => $id]);

            self::grants()->grantRole($below, $clerk, tenant: self::tenant($first), includeSubtree: false);
            self::grants()->grantRole($below, $auditor, tenant: self::tenant($second));
        }

        $report = null;

        self::assertSame($same + 1, self::queriesOf(static function () use ($clerk, $auditor, &$report): ConflictReport {
            return $report = self::report($clerk, $auditor);
        }));
        self::assertNotNull($report);
        self::assertSame(['one', 'two'], self::holderKeys($report));
        self::assertSame(0, $this->tree()->reads);
    }

    /**
     * Routes overlap only where a check sees both roles held: a grant reaching
     * below its tenant holds a role owned below it in the owner's subtree
     * alone, so two such roles owned side by side never conflict, nor does one
     * against a grant beside its owner, while one against a grant below its
     * owner does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRoutesOverlapOnlyWhereACheckSeesBothRolesHeld(): void
    {
        $clerk     = Role::query()->withoutGlobalScopes()->create(['name' => 'clerk', 'tenant_type' => self::TENANT, 'tenant_id' => 'child']);
        $auditor   = Role::query()->withoutGlobalScopes()->create(['name' => 'auditor', 'tenant_type' => self::TENANT, 'tenant_id' => 'sibling']);
        $requester = Role::query()->create(['name' => 'requester']);

        $second = [
            'apart'  => [$auditor, 'parent', true],
            'below'  => [$requester, 'grandchild', false],
            'beside' => [$requester, 'sibling', false],
        ];

        foreach ($second as $id => [$role, $tenant, $isReaching]) {
            $holder = StubIdentity::query()->create(['id' => $id]);

            self::insertGrant($clerk, $holder, self::tenant('parent'), true);
            self::insertGrant($role, $holder, self::tenant($tenant), $isReaching);
        }

        [$apart, $below] = self::read([[$clerk, $auditor], [$clerk, $requester]]);

        self::assertTrue($apart->isEmpty());
        self::assertSame(['below'], self::holderKeys($below));
        self::assertEquals(self::tenant('parent'), $below->conflicts[0]->first->scope->tenant);
        self::assertEquals(self::tenant('child'), $below->conflicts[0]->first->reach->tenant);
        self::assertSame(0, $this->tree()->reads);
    }

    /**
     * A grant at the platform holds a tenant's role in the tenant's subtree,
     * whether it reaches below or not, so it conflicts with a grant below the
     * owner and not with one beside it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformGrantOfATenantsRoleOverlapsOnlyWithinItsOwner(): void
    {
        $clerk     = Role::query()->withoutGlobalScopes()->create(['name' => 'clerk', 'tenant_type' => self::TENANT, 'tenant_id' => 'child']);
        $requester = Role::query()->create(['name' => 'requester']);

        foreach (['below' => 'grandchild', 'beside' => 'sibling'] as $id => $tenant) {
            $holder = StubIdentity::query()->create(['id' => $id]);

            self::insertGrant($clerk, $holder, null, false);
            self::insertGrant($requester, $holder, self::tenant($tenant), false);
        }

        self::assertSame(['below'], self::holderKeys(self::report($requester, $clerk)));
        self::assertSame(0, $this->tree()->reads);
    }

    /**
     * Read locked, the roles, their grants and their activations are read under
     * shared locks; read plain, as by default, nothing is locked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockedReadLocksTheRolesAndTheirGrants(): void
    {
        [$clerk, $auditor] = self::roles();

        self::grants()->grantRole(StubIdentity::query()->create(['id' => 'holder']), $clerk);

        $pairs  = [[Reference::of($clerk), Reference::of($auditor)]];
        $reader = new ConflictReader(new ListedIdentityDirectory);

        self::assertSame([], $this->lockedTables(static fn (): array => $reader->read($pairs)));
        self::assertSame(['authorizable_roles', 'break_glass_activations', 'roles'], $this->lockedTables(static fn (): array => $reader->read($pairs, true)));
    }

    /**
     * A role held through a parent role the grant's tenant no longer sees, once
     * the tree has moved the tenant away from the parent's owner, holds nothing
     * there, as a check there would find, so no conflict comes of it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParentRoleTheGrantsTenantNoLongerSeesHoldsNothing(): void
    {
        $approver  = Role::query()->withoutGlobalScopes()->create(['name' => 'approver', 'tenant_type' => self::TENANT, 'tenant_id' => 'parent']);
        $junior    = Role::query()->withoutGlobalScopes()->create(['name' => 'junior', 'parent_id' => $approver->id, 'tenant_type' => self::TENANT, 'tenant_id' => 'child']);
        $requester = Role::query()->create(['name' => 'requester']);
        $user      = StubIdentity::query()->create(['id' => 'user']);

        self::grants()->grantRole($user, $junior, tenant: self::tenant('child'));
        self::grants()->grantRole($user, $requester, tenant: self::tenant('child'));

        self::assertSame(['user'], self::holderKeys(self::report($approver, $requester)));

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(self::tenant('child'), self::tenant('other')));

        self::assertTrue(self::report($approver, $requester)->isEmpty());
        self::assertSame(['user'], self::holderKeys(self::report($junior, $requester)));
    }

    /**
     * Grants for every application overlap grants for any one, grants for the
     * same application overlap, and grants for two different applications never
     * do.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testApplicationsOverlapOnlyWhereTheyMeet(): void
    {
        [$clerk, $auditor] = self::roles();

        $holders = ['same' => ['admin', 'admin'], 'every' => [null, 'billing'], 'everyOther' => ['billing', null], 'apart' => ['admin', 'billing']];

        foreach ($holders as $id => [$first, $second]) {
            $holder = StubIdentity::query()->create(['id' => $id]);

            self::grants()->grantRole($holder, $clerk, application: $first);
            self::grants()->grantRole($holder, $auditor, application: $second);
        }

        self::assertSame(['every', 'everyOther', 'same'], self::holderKeys(self::report($clerk, $auditor)));
    }

    /**
     * A role held through its parent counts, its route naming the path from the
     * role granted up to the pair's role, until the hierarchy is turned off,
     * when a role is only its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleHeldThroughItsParentsCounts(): void
    {
        [$clerk, $auditor] = self::roles();

        $deputy = Role::query()->create(['name' => 'deputy', 'parent_id' => $clerk->id]);
        $acting = Role::query()->create(['name' => 'acting', 'parent_id' => $deputy->id]);
        $user   = StubIdentity::query()->create(['id' => 'user']);

        self::grants()->grantRole($user, $acting);
        self::grants()->grantRole($user, $auditor);

        $route = self::conflictOf(self::report($clerk, $auditor), $user)->first;

        self::assertFalse($route->isDirect());
        self::assertTrue(self::refersTo($route->granted(), $acting));
        self::assertSame([$acting->id, $deputy->id, $clerk->id], \array_map(static fn (Reference $role): string => $role->id, $route->path));

        config(['authorization.hierarchy.enabled' => false]);

        self::assertTrue(self::report($clerk, $auditor)->isEmpty());
    }

    /**
     * A principal holding one role itself and the other through its identity
     * conflicts, either way round, the identity named and its grant the route;
     * an identity holding both is its own holder; sibling principals of one
     * identity, and a machine principal of a person's identity, never conflict,
     * a machine told by its model class under its morph alias.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalAndItsIdentityAreWeighedTogether(): void
    {
        Relation::morphMap(['stub_machine' => StubMachine::class]);

        [$clerk, $auditor] = self::roles();

        $person  = StubIdentity::query()->create(['id' => 'person']);
        $both    = StubIdentity::query()->create(['id' => 'both']);
        $member  = StubSecondIdentity::query()->create(['id' => 'member']);
        $reverse = StubSecondIdentity::query()->create(['id' => 'reverse']);
        $first   = StubSecondIdentity::query()->create(['id' => 'first']);
        $second  = StubSecondIdentity::query()->create(['id' => 'second']);
        $machine = StubMachine::query()->create(['id' => 'machine']);
        $robots  = StubIdentity::query()->create(['id' => 'robots']);

        self::grants()->grantRole($person, $clerk);
        self::grants()->grantRole($member, $auditor);
        self::grants()->grantRole($reverse, $clerk);
        self::grants()->grantRole($both, $clerk);
        self::grants()->grantRole($both, $auditor);
        self::grants()->grantRole($first, $clerk);
        self::grants()->grantRole($second, $auditor);
        self::grants()->grantRole($robots, $clerk);
        self::grants()->grantRole($machine, $auditor);

        $directory = self::directory([
            'person' => [$member],
            'both'   => [$reverse, $both],
            'owner'  => [$first, $second],
            'robots' => [$machine],
        ]);

        $report = self::report($clerk, $auditor, $directory);

        self::assertSame(['both', 'member', 'reverse'], self::holderKeys($report));
        self::assertCount(3, $report->conflicts);
        self::assertNull(self::conflictOf($report, $both)->identity);

        $member = self::conflictOf($report, $member);

        self::assertTrue(self::refersTo($member->identity, $person));
        self::assertTrue(self::refersTo($member->first->grantee, $person));
        self::assertTrue(self::refersTo($member->second->grantee, StubSecondIdentity::query()->findOrFail('member')));

        $reverse = self::conflictOf($report, $reverse);

        self::assertTrue(self::refersTo($reverse->identity, $both));
        self::assertTrue(self::refersTo($reverse->second->grantee, $both));
        self::assertTrue($report->isComplete);
    }

    /**
     * A live break-glass activation conflicts with its holder's grant of the
     * other role, and a principal's own with its identity's grant, either way
     * round; an identity's activation never reaches its principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationIsWeighedAsTheSubjectsOwnGrant(): void
    {
        [$clerk, $auditor] = self::roles();

        $holder   = StubIdentity::query()->create(['id' => 'holder']);
        $identity = StubIdentity::query()->create(['id' => 'identity']);
        $active   = StubSecondIdentity::query()->create(['id' => 'active']);
        $first    = StubSecondIdentity::query()->create(['id' => 'first']);
        $second   = StubSecondIdentity::query()->create(['id' => 'second']);
        $other    = StubIdentity::query()->create(['id' => 'other']);

        self::activate($clerk, $holder);
        self::grants()->grantRole($holder, $auditor);
        self::activate($auditor, $active);
        self::grants()->grantRole($identity, $clerk);
        self::activate($clerk, $other);
        self::activate($auditor, $other);
        self::grants()->grantRole($first, $clerk);
        self::grants()->grantRole($second, $auditor);

        $report = self::report($clerk, $auditor, self::directory(['identity' => [$active], 'other' => [$first, $second]]));

        self::assertSame(['holder', 'other', 'active'], self::holderKeys($report));
        self::assertTrue(self::refersTo(self::conflictOf($report, $active)->identity, $identity));
    }

    /**
     * An expired grant and a grant naming half a tenant hold nothing, so
     * neither conflicts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExpiredAndHalfTenantGrantsHoldNothing(): void
    {
        [$clerk, $auditor] = self::roles();

        $expired = StubIdentity::query()->create(['id' => 'expired']);
        $half    = StubIdentity::query()->create(['id' => 'half']);

        Carbon::setTestNow('2026-07-01 12:00:00');

        self::grants()->grantRole($expired, $clerk, Carbon::now()->addHour());

        Carbon::setTestNow('2026-07-01 14:00:00');

        self::grants()->grantRole($expired, $auditor);
        self::grants()->grantRole($half, $clerk);

        DB::table('authorizable_roles')->insert([
            'role_id'           => $auditor->id,
            'authorizable_type' => $half->getMorphClass(),
            'authorizable_id'   => 'half',
            'tenant_type'       => self::TENANT,
            'include_subtree'   => true,
        ]);

        $report = self::report($clerk, $auditor);

        Carbon::setTestNow();

        self::assertTrue($report->isEmpty());
        self::assertSame([], $report->holders());
    }

    /**
     * Over a tree kept in a closure table whose tenants are of two types, a
     * subtree reaches across types, and tenants sharing a key under different
     * types are different tenants.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMixedTypeClosureTreeIsReadByTypeAndKey(): void
    {
        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        ClosureTenantTree::add(new Reference('org', '1'));
        ClosureTenantTree::add(new Reference('team', '1'), new Reference('org', '1'));
        ClosureTenantTree::add(new Reference('org', '2'));
        ClosureTenantTree::add(new Reference('team', '2'), new Reference('org', '2'));

        [$clerk, $auditor] = self::roles();

        $holders = [
            'across'    => [new Reference('org', '1'), true, new Reference('team', '1')],
            'elsewhere' => [new Reference('org', '1'), true, new Reference('team', '2')],
            'clash'     => [new Reference('org', '2'), false, new Reference('team', '1')],
        ];

        foreach ($holders as $id => [$first, $below, $second]) {
            $holder = StubIdentity::query()->create(['id' => $id]);

            self::grants()->grantRole($holder, $clerk, tenant: $first, includeSubtree: $below);
            self::grants()->grantRole($holder, $auditor, tenant: $second, includeSubtree: false);
        }

        self::assertSame(['across'], self::holderKeys(self::report($clerk, $auditor)));
    }

    /**
     * A report is incomplete when the directory listed a holder's principals
     * incompletely, and asks the directory once for each holder of either role,
     * never for anyone else.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIncompleteDirectoryMakesAnIncompleteReport(): void
    {
        [$clerk, $auditor] = self::roles();

        self::grants()->grantRole(StubIdentity::query()->create(['id' => 'one']), $clerk);
        self::grants()->grantRole(StubIdentity::query()->create(['id' => 'two']), $auditor);
        StubIdentity::query()->create(['id' => 'idle']);

        $directory = new ListedIdentityDirectory(isComplete: false);
        $reports   = self::read([[$clerk, $auditor], [Role::query()->create(['name' => 'idle-a']), Role::query()->create(['name' => 'idle-b'])]], $directory);

        self::assertFalse($reports[0]->isComplete);
        self::assertTrue($reports[0]->isEmpty());
        self::assertTrue($reports[1]->isComplete);
        self::assertSame(2, $directory->asked);
    }

    /**
     * Several pairs are read together, each report in the order asked, its
     * roles as given and its conflicts in a fixed order, in a fixed number of
     * queries however many holders there are; no pair reads nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSeveralPairsAreReadTogetherInAFixedNumberOfQueries(): void
    {
        [$clerk, $auditor] = self::roles();

        $payer = Role::query()->create(['name' => 'payer']);

        self::assertSame(0, self::queriesOf(static fn (): array => self::read([])));

        $holders = static function (int $from, int $to) use ($clerk, $auditor, $payer): void {
            foreach (\range($from, $to) as $number) {
                $holder = StubIdentity::query()->create(['id' => 'holder-' . \str_pad((string) $number, 3, '0', \STR_PAD_LEFT)]);

                self::grants()->grantRole($holder, $clerk, tenant: self::tenant('child'));
                self::grants()->grantRole($holder, $auditor, tenant: self::tenant('parent'));
                self::grants()->grantRole($holder, $payer, tenant: self::tenant('other'));
            }
        };

        $holders(1, 2);

        $few = self::queriesOf(static fn (): array => self::read([[$clerk, $auditor], [$auditor, $payer]]));

        $holders(3, 27);

        $reports = [];
        $many    = self::queriesOf(static function () use ($clerk, $auditor, $payer, &$reports): array {
            return $reports = self::read([[$clerk, $auditor], [$auditor, $payer]]);
        });

        self::assertSame($few, $many);
        self::assertCount(2, $reports);
        self::assertTrue(self::refersTo($reports[0]->role, $clerk));
        self::assertTrue(self::refersTo($reports[0]->excludedRole, $auditor));
        self::assertCount(27, $reports[0]->conflicts);
        self::assertSame('holder-001', $reports[0]->conflicts[0]->holder->id);
        self::assertSame('holder-027', $reports[0]->conflicts[26]->holder->id);
        self::assertTrue($reports[1]->isEmpty());
    }

    /**
     * A holder with several routes to each role conflicts once for each pair of
     * routes that overlap, in a fixed order.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachOverlappingPairOfRoutesIsOneConflict(): void
    {
        [$clerk, $auditor] = self::roles();

        $user = StubIdentity::query()->create(['id' => 'user']);

        self::grants()->grantRole($user, $clerk, tenant: self::tenant('child'));
        self::grants()->grantRole($user, $clerk, tenant: self::tenant('other'));
        self::grants()->grantRole($user, $auditor, tenant: self::tenant('child'));
        self::grants()->grantRole($user, $auditor);

        $conflicts = self::report($clerk, $auditor)->conflicts;
        $scopes    = \array_map(static fn (ExclusionConflict $conflict): array => [$conflict->first->scope->tenant?->id, $conflict->second->scope->tenant?->id], $conflicts);

        self::assertSame([['child', null], ['child', 'child'], ['other', null]], $scopes);
    }

    /**
     * Return the bound stub tenant tree.
     *
     * @return \Tests\Feature\Stubs\StubTenantTree
     */
    private function tree(): StubTenantTree
    {
        $tree = $this->app?->make(TenantTree::class);

        self::assertInstanceOf(StubTenantTree::class, $tree);

        return $tree;
    }

    /**
     * Return the report of the pair, read with the directory given, or one
     * listing no principals.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $excluded
     * @param  \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory|null  $directory
     * @return \SineMacula\Laravel\Authorization\Exclusions\ConflictReport
     *
     * @throws \Throwable
     */
    private static function report(Role $role, Role $excluded, ?IdentityDirectory $directory = null): ConflictReport
    {
        return self::read([[$role, $excluded]], $directory)[0];
    }

    /**
     * Return the reports of the pairs, read together.
     *
     * @param  list<array{0: \SineMacula\Laravel\Authorization\Models\Role, 1: \SineMacula\Laravel\Authorization\Models\Role}>  $pairs
     * @param  \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory|null  $directory
     * @return list<\SineMacula\Laravel\Authorization\Exclusions\ConflictReport>
     *
     * @throws \Throwable
     */
    private static function read(array $pairs, ?IdentityDirectory $directory = null): array
    {
        $reader = new ConflictReader($directory ?? new ListedIdentityDirectory);

        return $reader->read(\array_map(static fn (array $pair): array => [Reference::of($pair[0]), Reference::of($pair[1])], $pairs));
    }

    /**
     * Return the first conflict of the holder.
     *
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ConflictReport  $report
     * @param  \Illuminate\Database\Eloquent\Model  $holder
     * @return \SineMacula\Laravel\Authorization\Exclusions\ExclusionConflict
     */
    private static function conflictOf(ConflictReport $report, Model $holder): ExclusionConflict
    {
        foreach ($report->conflicts as $conflict) {
            if (self::refersTo($conflict->holder, $holder)) {
                return $conflict;
            }
        }

        self::fail('The holder has no conflict.');
    }

    /**
     * Return the keys of the report's holders, in its order.
     *
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ConflictReport  $report
     * @return list<string>
     */
    private static function holderKeys(ConflictReport $report): array
    {
        return \array_map(static fn (Reference $holder): string => $holder->id, $report->holders());
    }

    /**
     * Return the number of queries the read ran.
     *
     * @param  \Closure(): mixed  $read
     * @return int
     */
    private static function queriesOf(\Closure $read): int
    {
        $count = 0;

        DB::listen(static function (QueryExecuted $query) use (&$count): void {
            $count++;
        });

        $before = $count;

        $read();

        return $count - $before;
    }

    /**
     * Return a directory listing the principals of each identity by its key.
     *
     * @param  array<string, list<\Illuminate\Database\Eloquent\Model>>  $principals
     * @return \Tests\Fixtures\GrantScope\ListedIdentityDirectory
     */
    private static function directory(array $principals): ListedIdentityDirectory
    {
        $listed = [];

        foreach ($principals as $identity => $models) {
            $listed[ListedIdentityDirectory::key(new Reference((new StubIdentity)->getMorphClass(), $identity))] = \array_map(Reference::of(...), $models);
        }

        return new ListedIdentityDirectory($listed);
    }

    /**
     * Return two platform roles, `clerk` and `auditor`.
     *
     * @return array{0: \SineMacula\Laravel\Authorization\Models\Role, 1: \SineMacula\Laravel\Authorization\Models\Role}
     */
    private static function roles(): array
    {
        return [Role::query()->create(['name' => 'clerk']), Role::query()->create(['name' => 'auditor'])];
    }

    /**
     * Return the stub tenant with the key.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function tenant(string $id): Reference
    {
        return new Reference(self::TENANT, $id);
    }

    /**
     * Store a live break-glass activation of the role for the grantee at the
     * platform.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @return void
     */
    private static function activate(Role $role, Model $grantee): void
    {
        DB::table('break_glass_activations')->insert([
            'id'                => (string) Str::uuid(),
            'role_id'           => $role->id,
            'authorizable_type' => $grantee->getMorphClass(),
            'authorizable_id'   => $grantee->getKey(),
            'justification'     => 'incident',
            'activated_at'      => Carbon::now()->subHour(),
            'expires_at'        => Carbon::now()->addHour(),
        ]);
    }

    /**
     * Store a grant of the role as it is, past the grant service's owner rules,
     * as a tree move leaves one.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \Tests\Feature\Stubs\StubIdentity  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @return void
     */
    private static function insertGrant(Role $role, StubIdentity $grantee, ?Reference $tenant, bool $includeSubtree): void
    {
        DB::table('authorizable_roles')->insert([
            'role_id'           => $role->id,
            'authorizable_type' => $grantee->getMorphClass(),
            'authorizable_id'   => $grantee->getKey(),
            'tenant_type'       => $tenant?->type,
            'tenant_id'         => $tenant?->id,
            'include_subtree'   => $includeSubtree,
        ]);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        return app(GrantService::class);
    }
}
