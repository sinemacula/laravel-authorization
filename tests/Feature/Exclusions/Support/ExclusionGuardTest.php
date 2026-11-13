<?php

declare(strict_types = 1);

namespace Tests\Feature\Exclusions\Support;

use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\Role\Updated as RoleUpdated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\RoleExclusionConflictException;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute;
use SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionGuard;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleExclusionService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Concerns\RecordsRowLocks;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\Fixtures\LockModeRecordingGrammar;
use Tests\TestCase;

/**
 * Feature tests for `ExclusionGuard`: every write that can create a holding is
 * refused when it would leave someone holding both roles of a declared pair
 * where their reach overlaps, trusted or delegated, and nothing is written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ExclusionGuard::class)]
final class ExclusionGuardTest extends TestCase
{
    use ActsAsAdministrator, CatchesRefusals, ComparesReferences, ReadsDispatchedEvents, RecordsRowLocks;

    /** @var string The type of the stub tenants. */
    private const string TENANT = 'stub_tenant';

    /** @var string The name of the second session's connection. */
    private const string OTHER = 'bl71b_concurrent';

    /** @var list<string> The tests that race another session, run outside the test's transaction on MySQL and PostgreSQL. */
    private const array RACED = [
        'testAGrantSeesAPairCommittedAfterItsFirstRead',
        'testAGrantSeesAParentCommittedAfterItsFirstRead',
        'testGrantsOfAPairsRolesQueue',
        'testGrantsOfRolesInOverlappingPairsQueue',
        'testAParentQueuesBehindAGrantAPairTouches',
    ];

    /**
     * Put the stub tenants in a tree: `child` and `grandchild` below `parent`,
     * `sibling` beside `child`, and `other` at the top on its own.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
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
     * A grant of one role of a declared pair to a holder of the other is
     * refused with the report of the conflict it would create, through the
     * service and the model trait alike, and nothing is written or reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantThatWouldHoldBothRolesIsRefused(): void
    {
        [$clerk, $auditor] = self::declared();

        $user = StubIdentity::query()->create(['id' => 'user']);

        self::grants()->grantRole($user, $clerk);

        Event::fake([RoleAssigned::class]);

        $refusal = self::refusalOf(static fn () => self::grants()->grantRole($user, $auditor));

        self::assertInstanceOf(RoleExclusionConflictException::class, $refusal);
        self::assertSame('Roles \'clerk\' and \'auditor\' are mutually exclusive: the write would leave 1 holder holding both where their reach overlaps.', $refusal->getMessage());

        $report = $refusal->getReport();

        self::assertCount(1, $report->conflicts);
        self::assertTrue(self::refersTo($report->conflicts[0]->holder, $user));
        self::assertEqualsCanonicalizing([$clerk->id, $auditor->id], [$report->role->id, $report->excludedRole->id]);
        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => $user->assignRole($auditor)));
        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => $user->syncRoles([$auditor], self::tenant('child'))));
        self::assertSame(0, self::grantsOf($auditor));
        self::assertSame([], self::dispatchedEvents(RoleAssigned::class));
    }

    /**
     * A grant is refused where its reach overlaps the other role's, in one
     * tenant, below a tenant the other reaches, at the platform, in an
     * application the other holds everywhere, or through a role below the
     * pair's; it is allowed in a sibling tenant, below a grant limited to its
     * own tenant and in another application.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantIsRefusedOnlyWhereTheReachesOverlap(): void
    {
        [$clerk, $auditor] = self::declared();

        $junior = Role::query()->create(['name' => 'junior', 'parent_id' => $auditor->id]);
        $cases  = [
            'one tenant'    => [true, ['child', true, null], ['child', false, null], $auditor],
            'subtree'       => [true, ['parent', true, null], ['grandchild', true, null], $auditor],
            'platform'      => [true, [null, true, null], ['other', true, null], $auditor],
            'application'   => [true, ['child', true, null], ['child', true, 'admin'], $auditor],
            'inherited'     => [true, ['child', true, null], ['child', true, null], $junior],
            'sibling'       => [false, ['child', true, null], ['sibling', true, null], $auditor],
            'limited'       => [false, ['parent', false, null], ['child', true, null], $auditor],
            'other program' => [false, ['child', true, 'admin'], ['child', true, 'billing'], $auditor],
        ];

        foreach ($cases as $name => [$isRefused, $held, $granted, $role]) {
            $user  = StubIdentity::query()->create(['id' => \str_replace(' ', '-', $name)]);
            $grant = static fn (Role $role, array $scope): GrantOutcome => self::grants()->grantRole(
                $user,
                $role,
                tenant: $scope[0] === null ? null : self::tenant($scope[0]),
                includeSubtree: $scope[1],
                application: $scope[2],
            );

            $grant($clerk, $held);

            if ($isRefused) {
                self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => $grant($role, $granted)), $name);
            } else {
                self::assertSame(GrantOutcome::GRANTED, $grant($role, $granted), $name);
            }
        }
    }

    /**
     * A principal and its identity are weighed together, either way round, so a
     * grant to either that lets the principal hold both roles is refused, while
     * sibling principals of one identity never are.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalAndItsIdentityAreWeighedTogether(): void
    {
        [$clerk, $auditor] = self::declared();

        $person = StubIdentity::query()->create(['id' => 'person']);
        $member = StubSecondIdentity::query()->create(['id' => 'member']);
        $owner  = StubIdentity::query()->create(['id' => 'owner']);
        $first  = StubSecondIdentity::query()->create(['id' => 'first']);
        $second = StubSecondIdentity::query()->create(['id' => 'second']);

        $this->app?->instance(IdentityDirectory::class, new ListedIdentityDirectory([
            ListedIdentityDirectory::key(Reference::of($person)) => [Reference::of($member)],
            ListedIdentityDirectory::key(Reference::of($owner))  => [Reference::of($first), Reference::of($second)],
        ]));

        self::grants()->grantRole($person, $clerk);
        self::grants()->grantRole($first, $clerk);

        $refusal = self::refusalOf(static fn () => self::grants()->grantRole($member, $auditor));

        self::assertInstanceOf(RoleExclusionConflictException::class, $refusal);
        self::assertTrue(self::refersTo($refusal->getReport()->conflicts[0]->holder, $member));
        self::assertTrue(self::refersTo($refusal->getReport()->conflicts[0]->identity, $person));
        self::assertSame(GrantOutcome::GRANTED, self::grants()->grantRole($second, $auditor));

        self::grants()->revokeRole($person, $clerk);
        self::grants()->grantRole($member, $clerk);

        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => self::grants()->grantRole($person, $auditor)));
    }

    /**
     * A sync is weighed as it leaves the grantee's roles: replacing one role of
     * a pair with the other is allowed, and listing both is refused, keeping
     * what was held.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncIsWeighedAsItLeavesTheRoles(): void
    {
        [$clerk, $auditor] = self::declared();

        $swap = StubIdentity::query()->create(['id' => 'swap']);
        $both = StubIdentity::query()->create(['id' => 'both']);

        self::grants()->grantRole($swap, $clerk, tenant: self::tenant('child'));
        self::grants()->grantRole($both, $clerk, tenant: self::tenant('child'));

        $result = self::grants()->syncRoles($swap, [$auditor], tenant: self::tenant('child'));

        self::assertSame([$auditor->id], $result->granted);
        self::assertSame([$clerk->id], $result->revoked);
        $refusal = self::refusalOf(static fn () => self::grants()->syncRoles($both, [$clerk, $auditor], tenant: self::tenant('child')));

        self::assertInstanceOf(RoleExclusionConflictException::class, $refusal);
        self::assertSame(1, self::grantsOf($clerk));

        $lapsed = StubIdentity::query()->create(['id' => 'lapsed']);
        $other  = Role::query()->create(['name' => 'other']);

        self::grants()->grantRole($lapsed, $clerk);
        self::grants()->grantRole($lapsed, $other, tenant: self::tenant('child'));
        self::insertGrant($auditor, $lapsed, self::tenant('child'), false, Carbon::now()->subDay());

        foreach ([[$other, $auditor], [$auditor, $other]] as $listed) {
            $sync = static fn () => self::grants()->syncRoles($lapsed, $listed, tenant: self::tenant('child'));

            self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf($sync));
        }
    }

    /**
     * Only a write that may widen a grant is weighed: a grant left as it was, a
     * shorter expiry and a narrower reach go through beside a conflict already
     * stored, while a later expiry, a wider reach and a re-armed grant are
     * refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyAWriteThatMayWidenAGrantIsWeighed(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        [$clerk, $auditor] = self::declared();

        $user  = StubIdentity::query()->create(['id' => 'user']);
        $wide  = StubIdentity::query()->create(['id' => 'wide']);
        $week  = Carbon::now()->addWeek();
        $child = self::tenant('child');
        $grant = static fn (StubIdentity $grantee, ?\DateTimeInterface $until, bool $below = false): GrantOutcome => self::grants()
            ->grantRole($grantee, $auditor, $until, tenant: $child, includeSubtree: $below);

        self::grants()->grantRole($user, $clerk);
        self::grants()->grantRole($wide, $clerk);
        self::insertGrant($auditor, $user, $child, false, $week);
        self::insertGrant($auditor, $wide, $child, true, $week);

        self::assertSame(GrantOutcome::UNCHANGED, $grant($user, $week));
        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $grant($user, Carbon::now()->addDay()));
        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $grant($wide, Carbon::now()->addDay(), true));
        self::assertSame(GrantOutcome::REACH_CHANGED, $grant($wide, Carbon::now()->addDay()));
        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => $grant($user, $week)));
        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => $grant($user, Carbon::now()->addDay(), true)));

        $late = StubIdentity::query()->create(['id' => 'late']);

        self::grants()->grantRole($late, $clerk, tenant: self::tenant('grandchild'));
        self::grants()->grantRole($late, $auditor, tenant: $child, includeSubtree: false);

        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => $grant($late, null, true)));

        $lapsed = StubIdentity::query()->create(['id' => 'lapsed']);

        self::grants()->grantRole($lapsed, $clerk);
        self::insertGrant($auditor, $lapsed, $child, false, Carbon::now()->subDay());

        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => $grant($lapsed, null)));

        Carbon::setTestNow();
    }

    /**
     * A delegated grant is decided before it is weighed, so an actor not
     * allowed it is refused as such, and one allowed it is refused for the
     * conflict, as a trusted grant is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedGrantIsDecidedBeforeItIsWeighed(): void
    {
        [$clerk, $auditor] = self::declared(5);

        $nobody = self::administrator([], 'nobody', null);
        $admin  = self::administrator();
        $user   = StubIdentity::query()->create(['id' => 'user']);

        self::grants()->grantRole($user, $clerk);

        self::assertInstanceOf(AuthorizationException::class, self::refusalOf(static fn () => self::grants()->grantRole($user, $auditor, actor: $nobody)));
        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => self::grants()->grantRole($user, $auditor, actor: $admin)));
        self::assertSame(0, self::grantsOf($auditor));
    }

    /**
     * A parent that would let a holder of the role, or of a role below it, hold
     * both roles of a pair is refused through the service and the model alike,
     * trusted or delegated, leaving the parent as it was and reporting nothing;
     * another parent, and any while the hierarchy is disabled, is set, and a
     * save keeping the parent, or a parent cleared, is never weighed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParentThatWouldHoldBothRolesIsRefused(): void
    {
        [$clerk, $auditor] = self::declared(5);

        $intern  = Role::query()->create(['name' => 'intern', 'rank' => 6]);
        $trainee = Role::query()->create(['name' => 'trainee', 'rank' => 7, 'parent_id' => $intern->id]);
        $other   = Role::query()->create(['name' => 'other', 'rank' => 5]);
        $user    = StubIdentity::query()->create(['id' => 'user']);

        self::grants()->grantRole($user, $clerk);
        self::grants()->grantRole($user, $trainee);

        Event::fake([RoleUpdated::class]);

        $admin   = self::administrator();
        $refusal = self::refusalOf(static fn () => self::roles()->setParent($intern, $auditor));

        self::assertInstanceOf(RoleExclusionConflictException::class, $refusal);
        self::assertSame([$trainee->id, $intern->id, $auditor->id], \array_map(static fn (Reference $role): string => $role->id, self::routeTo($refusal, $auditor)->path));
        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => self::roles()->setParent($intern, $auditor, $admin)));
        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => $intern->forceFill(['parent_id' => $auditor->id])->save()));
        self::assertNull(Role::query()->whereKey($intern->getKey())->firstOrFail()->parent_id);
        self::assertSame([], self::dispatchedEvents(RoleUpdated::class));
        self::assertSame($other->id, self::roles()->setParent($intern->refresh(), $other)->parent_id);

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame($auditor->id, self::roles()->setParent($intern, $auditor)->parent_id);

        config(['authorization.hierarchy.enabled' => true]);

        self::assertSame('kept', self::roles()->describe($intern, 'kept')->description);

        ExclusionGuard::assertParent($trainee->forceFill(['parent_id' => null]));
    }

    /**
     * A break-glass activation is weighed as a live grant beside the stored
     * ones: refused where it would overlap the other role, allowed elsewhere.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABreakGlassActivationIsWeighedAsAGrant(): void
    {
        [$clerk, $auditor] = self::declared();

        $user = StubIdentity::query()->create(['id' => 'user']);

        self::grants()->grantRole($user, $clerk, tenant: self::tenant('child'));

        $refusal = self::refusalOf(static fn () => ExclusionGuard::assertActivatable(Reference::of($user), $auditor, new GrantScope(self::tenant('grandchild'))));

        self::assertInstanceOf(RoleExclusionConflictException::class, $refusal);
        self::assertTrue(self::refersTo(self::routeTo($refusal, $auditor)->grantee, $user));

        ExclusionGuard::assertActivatable(Reference::of($user), $auditor, new GrantScope(self::tenant('sibling')));
        ExclusionGuard::assertActivatable(Reference::of($user), $clerk, new GrantScope(self::tenant('grandchild')));
    }

    /**
     * A live break-glass activation is weighed as a holding: a grant of the
     * other role, and an activation of it, are refused while it lasts, and
     * allowed once it has ended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALiveActivationIsWeighedAsAHolding(): void
    {
        [$clerk, $auditor] = self::declared();

        $user = StubIdentity::query()->create(['id' => 'user']);

        self::activate($clerk, $user);

        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => self::grants()->grantRole($user, $auditor)));
        $activation = static fn () => ExclusionGuard::assertActivatable(Reference::of($user), $auditor, GrantScope::platform());

        self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf($activation));

        DB::table('break_glass_activations')->update(['ended_at' => Carbon::now()->subMinute()]);

        self::assertSame(GrantOutcome::GRANTED, self::grants()->grantRole($user, $auditor));
    }

    /**
     * A parent a pair touches locks the role and every role below it for update
     * before the report is read, whether it is refused or set.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParentAPairTouchesLocksTheRolesBelowTheRole(): void
    {
        [$clerk, $auditor] = self::declared();

        $intern  = Role::query()->create(['name' => 'intern']);
        $trainee = Role::query()->create(['name' => 'trainee', 'parent_id' => $intern->id]);
        $user    = StubIdentity::query()->create(['id' => 'user']);
        $below   = [$intern->id, $trainee->id];

        \sort($below);

        self::grants()->grantRole($user, $clerk);
        self::grants()->grantRole($user, $trainee);

        $refusal = null;
        $refused = $this->roleLockModes(static function () use ($intern, $auditor, &$refusal): void {
            $refusal = self::refusalOf(static fn () => self::roles()->setParent($intern, $auditor));
        });

        self::assertInstanceOf(RoleExclusionConflictException::class, $refusal);

        self::grants()->revokeRole($user, $trainee);

        $set = $this->roleLockModes(static fn () => self::roles()->setParent($intern, $auditor));

        self::assertContains([true, $below], $refused);
        self::assertContains([true, $below], $set);
    }

    /**
     * A grant no pair touches costs the one query that walks up from its role,
     * under a shared lock, and a permission grant none; one a pair touches
     * locks no role for update and reads the report under shared locks, unless
     * it leaves the grant as it was, which reads no report.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantNoPairTouchesReadsThePairsOnce(): void
    {
        $idle = Role::query()->create(['name' => 'idle']);
        $user = StubIdentity::query()->create(['id' => 'user']);

        Permission::query()->create(['name' => 'posts:edit']);

        $resolved = 0;
        $queries  = [];

        $this->app?->resolving(IdentityDirectory::class, static function () use (&$resolved): void {
            $resolved++;
        });

        $locks = $this->roleLockModes(static function () use ($user, $idle, &$queries): void {
            $queries = self::queriesOf(static fn () => self::grants()->grantRole($user, $idle));
        });

        self::assertCount(1, \array_filter($queries, static fn (string $sql): bool => \str_contains($sql, 'role_exclusions')));
        self::assertSame([[false, [$idle->id]]], $locks);
        self::assertSame(0, $resolved);
        self::assertSame([], self::queriesNaming('role_exclusions', static fn () => self::grants()->grantPermission($user, 'posts:edit')));

        [, $auditor] = self::declared();

        $tables = $this->lockedTables(static fn () => self::grants()->grantRole($user, $auditor, Carbon::now()->addDay()));
        $modes  = $this->roleLockModes(static fn () => self::grants()->grantRole($user, $auditor));

        self::assertSame(['authorizable_roles', 'break_glass_activations', 'role_exclusions', 'roles'], $tables);
        self::assertSame([false, [$auditor->id]], $modes[0]);
        self::assertNotContains(true, \array_column($modes, 0));
        self::assertSame([], self::queriesNaming('break_glass', static fn () => self::grants()->grantRole($user, $auditor)));
    }

    /**
     * A grant of a role a pair touches, or of the pair's other role, waits for
     * a grant of either still running, before it writes, and is weighed against
     * what the first committed (MySQL and PostgreSQL).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGrantsOfAPairsRolesQueue(): void
    {
        $this->raceOrSkip(static function (): void {
            $clerk   = Role::query()->create(['name' => 'clerk']);
            $auditor = Role::query()->create(['name' => 'auditor']);
            $first   = StubIdentity::query()->create(['id' => 'first']);
            $second  = StubIdentity::query()->create(['id' => 'second']);

            self::exclusions()->declare($clerk, $auditor);

            self::assertWaits(static fn () => self::grants()->grantRole($first, $clerk), static fn () => self::grants()->grantRole($second, $clerk));
            self::assertWaits(static fn () => self::grants()->grantRole($second, $clerk), static fn () => self::grants()->grantRole($first, $auditor));
            self::assertSame(2, self::grantsOf($clerk));
            self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => self::grants()->grantRole($first, $auditor)));
        });
    }

    /**
     * Grants of two roles of a pair queue when each role is also in a pair the
     * other is not, whichever pair each finds first, so only one of them
     * commits (MySQL and PostgreSQL).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGrantsOfRolesInOverlappingPairsQueue(): void
    {
        $this->raceOrSkip(static function (): void {
            [$first, $second, $third] = self::keyedRoles(['first', 'second', 'third']);

            $user = StubIdentity::query()->create(['id' => 'user']);

            self::exclusions()->declare($first, $second);
            self::exclusions()->declare($first, $third);
            self::exclusions()->declare($second, $third);

            self::assertWaits(static fn () => self::grants()->grantRole($user, $second), static fn () => self::grants()->grantRole($user, $third));
            self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => self::grants()->grantRole($user, $third)));
            self::assertSame([1, 0], [self::grantsOf($second), self::grantsOf($third)]);
        });
    }

    /**
     * A parent given to a role while a grant a pair touches is running waits
     * for it, though each finds another pair first, and is weighed against what
     * the grant committed (MySQL and PostgreSQL).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParentQueuesBehindAGrantAPairTouches(): void
    {
        $this->raceOrSkip(static function (): void {
            [$clerk, $intern, $auditor, $approver, $trainee] = self::keyedRoles(['clerk', 'intern', 'auditor', 'approver', 'trainee']);

            $user = StubIdentity::query()->create(['id' => 'user']);

            self::exclusions()->declare($clerk, $auditor);
            self::exclusions()->declare($intern, $approver);
            self::exclusions()->declare($auditor, $approver);
            self::grants()->grantRole($user, $trainee);

            self::assertWaits(static fn () => self::grants()->grantRole($user, $approver), static fn () => self::roles()->setParent($trainee, $auditor));
            self::assertInstanceOf(RoleExclusionConflictException::class, self::refusalOf(static fn () => self::roles()->setParent($trainee, $auditor)));
            self::assertNull($trainee->refresh()->parent_id);
        });
    }

    /**
     * The roles below a pair are locked for update with the pair's, in key
     * order, or the pair's alone while the hierarchy is disabled.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLocksTheRolesAndTheRolesBelowThem(): void
    {
        $clerk  = (new Role)->forceFill(['id' => '00000000-0000-4000-8000-0000000000ff', 'name' => 'clerk']);
        $junior = (new Role)->forceFill(['id' => '00000000-0000-4000-8000-000000000001', 'name' => 'junior', 'parent_id' => $clerk->id]);

        $clerk->save();
        $junior->save();

        $locks = $this->recordRowLocks();

        ExclusionGuard::lockBelow([$clerk->id]);

        config(['authorization.hierarchy.enabled' => false]);

        ExclusionGuard::lockBelow([$clerk->id]);

        self::assertSame([['roles', [$junior->id, $clerk->id]], ['roles', [$clerk->id]]], self::roleLocks($locks));
    }

    /**
     * A grant sees a pair another session committed after the grant's first
     * read, and is refused, so neither wins over the other and no one ends
     * holding both roles (MySQL and PostgreSQL).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantSeesAPairCommittedAfterItsFirstRead(): void
    {
        $this->raceOrSkip(static function (): void {
            $clerk   = Role::query()->create(['name' => 'clerk']);
            $auditor = Role::query()->create(['name' => 'auditor']);
            $user    = StubIdentity::query()->create(['id' => 'user']);
            $pair    = [$clerk->id, $auditor->id];

            \sort($pair);

            self::grants()->grantRole($user, $clerk);

            $refusal = self::refusalOf(static fn () => self::afterFirstRead(
                static fn () => self::grants()->grantRole($user, 'auditor'),
                static fn (Connection $other) => $other->table('role_exclusions')->insert(['role_id' => $pair[0], 'excluded_role_id' => $pair[1]]),
            ));

            self::assertInstanceOf(RoleExclusionConflictException::class, $refusal);
            self::assertTrue(self::exclusions()->conflictsForAll()[0]->isEmpty());
        });
    }

    /**
     * A grant sees a parent another session gave its role after the grant's
     * first read, so a pair it reaches through the parent refuses it: the roles
     * above are read as last committed, never as the transaction's snapshot
     * shows them (MySQL and PostgreSQL).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantSeesAParentCommittedAfterItsFirstRead(): void
    {
        $this->raceOrSkip(static function (): void {
            [$clerk, $auditor] = self::declared();

            $intern = Role::query()->create(['name' => 'intern']);
            $user   = StubIdentity::query()->create(['id' => 'user']);

            self::grants()->grantRole($user, $auditor);

            $refusal = self::refusalOf(static fn () => self::afterFirstRead(
                static fn () => self::grants()->grantRole($user, 'intern'),
                static fn (Connection $other) => $other->table('roles')->where('id', $intern->id)->update(['parent_id' => $clerk->id]),
            ));

            self::assertInstanceOf(RoleExclusionConflictException::class, $refusal);
            self::assertTrue(self::exclusions()->conflictsForAll()[0]->isEmpty());
        });
    }

    /**
     * A parent a pair touches, saved on the model outside any transaction on
     * the package's connection, which could not hold the check's locks to the
     * save, is refused, and the role keeps its parent; one no pair touches, a
     * role created with one, and any while the hierarchy is disabled, are
     * saved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParentSavedOutsideATransactionIsRefusedWhereAPairTouchesIt(): void
    {
        [, $auditor] = self::declared();

        $intern = Role::query()->create(['name' => 'intern']);
        $other  = Role::query()->create(['name' => 'other']);

        // A second connection on the test's session, so the test's own
        // transaction is not one the package's connection has open.
        config(['database.connections.' . self::OTHER => DB::connection()->getConfig(), 'authorization.connection' => self::OTHER]);
        DB::connection(self::OTHER)->setPdo(DB::connection()->getPdo());

        $refusal = self::refusalOf(static fn () => $intern->forceFill(['parent_id' => $auditor->id])->save());

        self::assertInstanceOf(\LogicException::class, $refusal);
        self::assertSame('Change a role\'s parent through RoleService::setParent() or inside a transaction.', $refusal->getMessage());
        self::assertNull(Role::query()->whereKey($intern->getKey())->firstOrFail()->parent_id);
        self::assertTrue($intern->refresh()->forceFill(['parent_id' => $other->id])->save());
        self::assertSame($auditor->id, Role::query()->create(['name' => 'junior', 'parent_id' => $auditor->id])->parent_id);

        config(['authorization.hierarchy.enabled' => false]);

        self::assertTrue($intern->forceFill(['parent_id' => $auditor->id])->save());

        config(['authorization.hierarchy.enabled' => true, 'authorization.connection' => null]);

        $intern->forceFill(['parent_id' => $other->id])->save();

        self::assertSame($auditor->id, self::roles()->setParent($intern, $auditor)->parent_id);
    }

    /**
     * Run the races outside the test's transaction, so the grant sees what
     * another session commits; SQLite, which skips them, keeps its transaction.
     *
     * @return list<string|null>
     */
    #[\Override]
    protected function connectionsToTransact(): array
    {
        $isRaced = \in_array($this->name(), self::RACED, true) && DB::connection()->getDriverName() !== 'sqlite';

        /** @var list<string|null> $connections */
        $connections = parent::connectionsToTransact();

        return $isRaced ? [] : $connections;
    }

    /**
     * Run the race on MySQL and PostgreSQL, outside the test's transaction,
     * with a second session on the package's connection, deleting what it
     * stored once it ends; SQLite, which has one writer, skips it.
     *
     * @param  \Closure(): void  $race
     * @return void
     *
     * @throws \Throwable
     */
    private function raceOrSkip(\Closure $race): void
    {
        $connection = DB::connection();

        if ($connection->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite has one writer, so nothing commits while a grant runs.');
        }

        config(['database.connections.' . self::OTHER => $connection->getConfig()]);

        try {
            $race();
        } finally {
            DB::table('roles')->update(['parent_id' => null]);

            foreach (['role_exclusions', 'authorizable_roles', 'roles', 'stub_identities'] as $table) {
                DB::table($table)->delete();
            }

            DB::purge(self::OTHER);
        }
    }

    /**
     * Run the grant, committing the change on a second session once the grant
     * has made its first read inside its transaction, which fixes its snapshot
     * on MySQL.
     *
     * @param  \Closure(): mixed  $grant
     * @param  \Closure(\Illuminate\Database\Connection): mixed  $change
     * @return mixed
     */
    private static function afterFirstRead(\Closure $grant, \Closure $change): mixed
    {
        $package = DB::connection();
        $isDone  = false;

        DB::listen(static function (QueryExecuted $query) use ($package, $change, &$isDone): void {
            if ($isDone || $query->connectionName !== $package->getName() || $package->transactionLevel() === 0 || !\str_starts_with(\strtolower($query->sql), 'select')) {
                return;
            }

            $isDone = true;

            $change(DB::connection(self::OTHER));
        });

        return $grant();
    }

    /**
     * Run the write and, once it has written its grant, run the concurrent
     * write on a second session that waits no longer than a second for a lock,
     * rolling it back, and assert it waited for the first until it gave up.
     *
     * @param  \Closure(): mixed  $write
     * @param  \Closure(): mixed  $concurrent
     * @return void
     */
    private static function assertWaits(\Closure $write, \Closure $concurrent): void
    {
        $package = DB::connection();
        $other   = DB::connection(self::OTHER);
        $isDone  = false;

        /** @var \ArrayObject<int, \Throwable> $waited */
        $waited = new \ArrayObject;

        $other->statement($other->getDriverName() === 'mysql' ? 'set session innodb_lock_wait_timeout = 1' : 'set lock_timeout = \'1s\'');

        DB::listen(static function (QueryExecuted $query) use ($package, $other, $concurrent, $waited, &$isDone): void {
            if ($isDone || $query->connectionName !== $package->getName() || !\str_starts_with($query->sql, 'insert') || !\str_contains($query->sql, 'authorizable_roles')) {
                return;
            }

            $isDone = true;

            config(['authorization.connection' => self::OTHER]);
            $other->beginTransaction();

            try {
                $waited->append(self::refusalOf($concurrent));
            } finally {
                $other->rollBack();
                config(['authorization.connection' => null]);
            }
        });

        $write();

        self::assertMatchesRegularExpression('/lock timeout|Lock wait timeout/', ($waited->getArrayCopy()[0] ?? null)?->getMessage() ?? '');
    }

    /**
     * Run the call and return each lock it took on rows of the roles table, in
     * order: whether it was for update, and its bindings.
     *
     * @param  \Closure(): mixed  $call
     * @return list<array{0: bool, 1: list<mixed>}>
     */
    private function roleLockModes(\Closure $call): array
    {
        $connection = DB::connection();
        $locks      = new \ArrayObject;

        if ($connection->getDriverName() === 'sqlite') {
            $connection->setQueryGrammar(new LockModeRecordingGrammar($connection, $locks));
        } else {
            DB::listen(static function (QueryExecuted $query) use ($locks): void {
                $sql = \strtolower($query->sql);

                if (\preg_match('/( for update| for share| lock in share mode)$/', $sql, $mode) !== 1) {
                    return;
                }

                $locks->append([self::lockedTable($sql), $mode[1] === ' for update', \array_values($query->bindings)]);
            });
        }

        try {
            $call();
        } finally {
            $connection->useDefaultQueryGrammar();
        }

        /** @var list<array{0: string, 1: bool, 2: list<mixed>}> $taken */
        $taken = $locks->getArrayCopy();

        return \array_values(\array_map(static fn (array $lock): array => [$lock[1], $lock[2]], \array_filter($taken, static fn (array $lock): bool => $lock[0] === 'roles')));
    }

    /**
     * Return the refusal's first route to the role.
     *
     * @param  \Throwable  $refusal
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return \SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute
     */
    private static function routeTo(\Throwable $refusal, Role $role): ExclusionRoute
    {
        self::assertInstanceOf(RoleExclusionConflictException::class, $refusal);

        $conflict = $refusal->getReport()->conflicts[0];

        return $conflict->first->role->id === $role->id ? $conflict->first : $conflict->second;
    }

    /**
     * Return two platform roles, `clerk` and `auditor`, of the rank given,
     * declared mutually exclusive.
     *
     * @param  int|null  $rank
     * @return array{0: \SineMacula\Laravel\Authorization\Models\Role, 1: \SineMacula\Laravel\Authorization\Models\Role}
     *
     * @throws \Throwable
     */
    private static function declared(?int $rank = null): array
    {
        $clerk   = Role::query()->create(['name' => 'clerk', 'rank' => $rank]);
        $auditor = Role::query()->create(['name' => 'auditor', 'rank' => $rank]);

        self::exclusions()->declare($clerk, $auditor);

        return [$clerk, $auditor];
    }

    /**
     * Create a role for each name, their keys in the order of the names.
     *
     * @param  list<string>  $names
     * @return list<\SineMacula\Laravel\Authorization\Models\Role>
     */
    private static function keyedRoles(array $names): array
    {
        $roles = [];

        foreach ($names as $index => $name) {
            $role = (new Role)->forceFill(['id' => \sprintf('00000000-0000-4000-8000-%012d', $index + 1), 'name' => $name]);

            $role->save();

            $roles[] = $role;
        }

        return $roles;
    }

    /**
     * Return the SQL of each query the call ran.
     *
     * @param  \Closure(): mixed  $call
     * @return list<string>
     */
    private static function queriesOf(\Closure $call): array
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        try {
            $call();
        } finally {
            DB::disableQueryLog();
        }

        return \array_column(DB::getQueryLog(), 'query');
    }

    /**
     * Return the SQL of each query the call ran that names the text given.
     *
     * @param  string  $text
     * @param  \Closure(): mixed  $call
     * @return list<string>
     */
    private static function queriesNaming(string $text, \Closure $call): array
    {
        return \array_values(\array_filter(self::queriesOf($call), static fn (string $sql): bool => \str_contains($sql, $text)));
    }

    /**
     * Store a live break-glass activation of the role for the grantee at the
     * platform.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \Tests\Feature\Stubs\StubIdentity  $grantee
     * @return void
     */
    private static function activate(Role $role, StubIdentity $grantee): void
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
     * Return how many grants of the role are stored.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return int
     */
    private static function grantsOf(Role $role): int
    {
        return DB::table('authorizable_roles')->where('role_id', $role->id)->count();
    }

    /**
     * Store a grant of the role as it is, past the guard, as a grant made
     * before a pair was declared is.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \Tests\Feature\Stubs\StubIdentity  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  bool  $includeSubtree
     * @param  \DateTimeInterface  $expiresAt
     * @return void
     */
    private static function insertGrant(Role $role, StubIdentity $grantee, Reference $tenant, bool $includeSubtree, \DateTimeInterface $expiresAt): void
    {
        DB::table('authorizable_roles')->insert([
            'role_id'           => $role->id,
            'authorizable_type' => $grantee->getMorphClass(),
            'authorizable_id'   => $grantee->getKey(),
            'tenant_type'       => $tenant->type,
            'tenant_id'         => $tenant->id,
            'include_subtree'   => $includeSubtree,
            'expires_at'        => $expiresAt,
        ]);
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
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        return app(GrantService::class);
    }

    /**
     * Return the role service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleService
     */
    private static function roles(): RoleService
    {
        return app(RoleService::class);
    }

    /**
     * Return the role exclusion service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleExclusionService
     */
    private static function exclusions(): RoleExclusionService
    {
        return app(RoleExclusionService::class);
    }
}
