<?php

declare(strict_types = 1);

namespace Tests\Feature\Exclusions\Support;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute;
use SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionHoldings;
use SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionWrite;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\Support\TenantRelations;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\RecordsRowLocks;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `ExclusionHoldings`: who holds each role of a set, and
 * through which live grants, directly or through roles below it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExclusionHoldings::class)]
final class ExclusionHoldingsTest extends TestCase
{
    use ActivatesBreakGlass, ActsAsTenant, ComparesReferences, RecordsRowLocks;

    /**
     * Given a write, the holdings are read as it would leave them: a role given
     * a parent below the role read is read with the roles below it, its holders
     * holding the role through the new parent, and no longer through the old; a
     * grant proposed is read as a live grant beside the stored ones.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWriteIsReadAsItWouldLeaveTheHoldings(): void
    {
        $clerk   = Role::query()->create(['name' => 'clerk']);
        $auditor = Role::query()->create(['name' => 'auditor']);
        $intern  = Role::query()->create(['name' => 'intern']);
        $trainee = Role::query()->create(['name' => 'trainee', 'parent_id' => $intern->id]);
        $junior  = Role::query()->create(['name' => 'junior', 'parent_id' => $auditor->id]);
        $user    = StubIdentity::query()->create(['id' => 'user']);
        $other   = StubIdentity::query()->create(['id' => 'other']);
        $tenant  = new Reference('stub_tenant', 'a');

        self::grants()->grantRole($user, $trainee);
        self::grants()->grantRole($user, $junior);

        $adopted = ExclusionHoldings::read([$clerk->id], new TenantRelations, write: ExclusionWrite::reparented($intern->id, $clerk->id));
        $moved   = ExclusionHoldings::read([$auditor->id], new TenantRelations, write: ExclusionWrite::reparented($junior->id, $clerk->id));
        $granted = ExclusionHoldings::read([$clerk->id], new TenantRelations, write: ExclusionWrite::proposed(Reference::of($other), $clerk->id, new GrantScope($tenant)));

        self::assertSame([], ExclusionHoldings::read([$clerk->id], new TenantRelations)->of($clerk->id, Reference::of($user)));
        self::assertSame([$trainee->id, $intern->id, $clerk->id], self::pathOf($adopted->of($clerk->id, Reference::of($user))[0]->path));
        self::assertCount(1, ExclusionHoldings::read([$auditor->id], new TenantRelations)->of($auditor->id, Reference::of($user)));
        self::assertSame([], $moved->of($auditor->id, Reference::of($user)));

        $route = $granted->of($clerk->id, Reference::of($other))[0];

        self::assertEquals($tenant, $route->scope->tenant);
        self::assertNull($route->expiresAt);
        self::assertTrue(self::refersTo($route->grantee, $other));
    }

    /**
     * Each live grant of a role, or of a role below it, is a route to it, in
     * every tenant and application, its path from the role granted up to the
     * role, its scope and expiry as stored; a role below two of the roles is a
     * route to each.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachGrantOfARoleOrARoleBelowItIsARoute(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $clerk   = Role::query()->create(['name' => 'clerk']);
        $auditor = Role::query()->create(['name' => 'auditor', 'parent_id' => $clerk->id]);
        $intern  = Role::query()->create(['name' => 'intern', 'parent_id' => $auditor->id]);
        $user    = StubIdentity::query()->create(['id' => 'user']);
        $tenant  = new Reference('stub_tenant', 'a');
        $until   = Carbon::now()->addDay();

        self::grants()->grantRole($user, $clerk, $until, tenant: $tenant, includeSubtree: false, application: 'admin');
        self::grants()->grantRole($user, $intern);

        $holdings = ExclusionHoldings::read([$clerk->id, $auditor->id], new TenantRelations);

        Carbon::setTestNow();

        $clerks   = $holdings->of($clerk->id, Reference::of($user));
        $auditors = $holdings->of($auditor->id, Reference::of($user));

        self::assertCount(2, $clerks);
        self::assertCount(1, $auditors);

        [$direct, $inherited] = $clerks[0]->isDirect() ? $clerks : \array_reverse($clerks);

        self::assertTrue(self::refersTo($direct->grantee, $user));
        self::assertTrue(self::refersTo($direct->role, $clerk));
        self::assertSame([$clerk->id], self::pathOf($direct->path));
        self::assertEquals($tenant, $direct->scope->tenant);
        self::assertSame('admin', $direct->scope->application);
        self::assertFalse($direct->scope->includeSubtree);
        self::assertSame('2026-07-02T12:00:00+00:00', $direct->expiresAt?->format(\DATE_ATOM));
        self::assertSame([$intern->id, $auditor->id, $clerk->id], self::pathOf($inherited->path));
        self::assertNull($inherited->expiresAt);
        self::assertSame([$intern->id, $auditor->id], self::pathOf($auditors[0]->path));
        self::assertTrue(self::refersTo($auditors[0]->role, $auditor));
    }

    /**
     * An expired grant and a grant naming half a tenant are no route, a role
     * above the roles read is never one, and a grantee with no route holds
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExpiredHalfTenantAndUnrelatedGrantsAreNoRoute(): void
    {
        $chief = Role::query()->create(['name' => 'chief']);
        $clerk = Role::query()->create(['name' => 'clerk', 'parent_id' => $chief->id]);
        $user  = StubIdentity::query()->create(['id' => 'user']);
        $idle  = StubIdentity::query()->create(['id' => 'idle']);

        Carbon::setTestNow('2026-07-01 12:00:00');

        self::grants()->grantRole($user, $clerk, Carbon::now()->addMinute());

        Carbon::setTestNow('2026-07-01 13:00:00');

        self::grants()->grantRole($user, $chief);

        DB::table('authorizable_roles')->insert([
            'role_id'           => $clerk->id,
            'authorizable_type' => $user->getMorphClass(),
            'authorizable_id'   => 'user',
            'tenant_id'         => 'a',
            'include_subtree'   => true,
        ]);

        $holdings = ExclusionHoldings::read([$clerk->id], new TenantRelations);

        Carbon::setTestNow();

        self::assertSame([], $holdings->of($clerk->id, Reference::of($user)));
        self::assertSame([], $holdings->of($clerk->id, Reference::of($idle)));
        self::assertSame([], $holdings->holders($clerk->id));
    }

    /**
     * The holders of the roles given are each grantee holding any of them,
     * once, under its key, and a role no one holds has none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testListsTheHoldersOfTheRolesGiven(): void
    {
        $clerk   = Role::query()->create(['name' => 'clerk']);
        $auditor = Role::query()->create(['name' => 'auditor']);
        $idle    = Role::query()->create(['name' => 'idle']);
        $one     = StubIdentity::query()->create(['id' => 'one']);
        $two     = StubIdentity::query()->create(['id' => 'two']);

        self::grants()->grantRole($one, $clerk);
        self::grants()->grantRole($one, $auditor);
        self::grants()->grantRole($two, $auditor);

        $holdings = ExclusionHoldings::read([$clerk->id, $auditor->id, $idle->id], new TenantRelations);

        self::assertSame([ExclusionHoldings::key(Reference::of($one))], \array_keys($holdings->holders($clerk->id)));
        self::assertSame(['one', 'two'], \array_map(static fn (Reference $holder): string => $holder->id, \array_values($holdings->holders($clerk->id, $auditor->id))));
        self::assertSame([], $holdings->holders($idle->id));
        self::assertSame([], $holdings->holders());
        self::assertSame(\serialize([$one->getMorphClass(), 'one']), ExclusionHoldings::key(Reference::of($one)));
        self::assertContainsOnlyInstancesOf(ExclusionRoute::class, $holdings->of($auditor->id, Reference::of($two)));
    }

    /**
     * The grants and the activations are read a chunk of the roles at a time,
     * so a set of roles larger than one chunk is read whole.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGrantsOfManyRolesAreReadAChunkAtATime(): void
    {
        $user  = StubIdentity::query()->create(['id' => 'user']);
        $roles = [];

        foreach (\range(1, 501) as $number) {
            $roles[] = Role::query()->create(['name' => 'role-' . $number])->id;
        }

        self::grants()->grantRole($user, Role::query()->findOrFail(\end($roles)));
        self::activate(Role::query()->findOrFail(\end($roles)), Reference::of($user), null, Carbon::now()->addHour());

        self::assertCount(2, ExclusionHoldings::read($roles, new TenantRelations)->of(\end($roles), Reference::of($user)));
    }

    /**
     * A grant holds a role through its parents only as far as a check sees
     * them: once the tree moves the grant's tenant away from the owner of a
     * parent role, the chain ends below it, and a role granted where its owner
     * is not seen holds nothing; the tree is asked about the owners together,
     * never one pair at a time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantHoldsOnlyTheRolesItsTenantSees(): void
    {
        [$parent, $child, $other] = \array_map(self::createTenant(...), ['parent', 'child', 'other']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($parent)));

        $approver = Role::query()->withoutGlobalScopes()->create(['name' => 'approver', ...self::ownedBy($parent)]);
        $junior   = Role::query()->withoutGlobalScopes()->create(['name' => 'junior', 'parent_id' => $approver->id, ...self::ownedBy($child)]);
        $user     = StubIdentity::query()->create(['id' => 'user']);

        self::grants()->grantRole($user, $junior, tenant: Reference::of($child));

        $before = ExclusionHoldings::read([$approver->id, $junior->id], new TenantRelations);

        $route = $before->of($approver->id, Reference::of($user))[0];

        self::assertSame([$junior->id, $approver->id], self::pathOf($route->path));
        self::assertSame($route->scope, $route->reach);

        $moved = (new StubTenantTree)->put(Reference::of($child), Reference::of($other));

        $this->app?->instance(TenantTree::class, $moved);

        $hidden = StubIdentity::query()->create(['id' => 'hidden']);

        self::insertGrant($approver, $hidden, Reference::of($child), true);

        $after = ExclusionHoldings::read([$approver->id, $junior->id], new TenantRelations);

        self::assertSame([], $after->of($approver->id, Reference::of($user)));
        self::assertCount(1, $after->of($junior->id, Reference::of($user)));
        self::assertSame([], $after->holders($approver->id));
        self::assertSame(0, $moved->reads);
    }

    /**
     * A grant reaching below its tenant holds a role owned below it, held in
     * the owner's subtree, as a check there sees it; limited to its tenant, it
     * holds nothing. A grant at the platform holds a tenant's role in the
     * tenant's subtree, for its own application.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantHoldsARoleOwnedBelowItWhereItsOwnerIs(): void
    {
        [$top, $below] = \array_map(self::createTenant(...), ['top', 'below']);

        $tree = (new StubTenantTree)->put(Reference::of($below), Reference::of($top));

        $this->app?->instance(TenantTree::class, $tree);

        $approver = Role::query()->withoutGlobalScopes()->create(['name' => 'approver', ...self::ownedBy($below)]);
        $reaching = StubIdentity::query()->create(['id' => 'reaching']);
        $limited  = StubIdentity::query()->create(['id' => 'limited']);
        $platform = StubIdentity::query()->create(['id' => 'platform']);

        self::insertGrant($approver, $reaching, Reference::of($top), true);
        self::insertGrant($approver, $limited, Reference::of($top), false);
        self::insertGrant($approver, $platform, null, false, 'admin');

        $holdings = ExclusionHoldings::read([$approver->id], new TenantRelations);
        $reached  = $holdings->of($approver->id, Reference::of($reaching));
        $placed   = $holdings->of($approver->id, Reference::of($platform));

        self::assertCount(1, $reached);
        self::assertEquals(new GrantScope(Reference::of($top)), $reached[0]->scope);
        self::assertEquals(new GrantScope(Reference::of($below)), $reached[0]->reach);
        self::assertSame([], $holdings->of($approver->id, Reference::of($limited)));
        self::assertCount(1, $placed);
        self::assertEquals(new GrantScope(null, 'admin', false), $placed[0]->scope);
        self::assertEquals(new GrantScope(Reference::of($below), 'admin'), $placed[0]->reach);
        self::assertSame(0, $tree->reads);
    }

    /**
     * A chain held below the grant's tenant ends at a parent role no tenant
     * there sees: one owned beside the role below it, not above it; a parent
     * owned by the grant's tenant is held where the role below it is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChainEndsWhereNoTenantSeesItsOwnersTogether(): void
    {
        [$top, $left, $right] = \array_map(self::createTenant(...), ['top', 'left', 'right']);

        $tree = (new StubTenantTree)->put(Reference::of($left), Reference::of($top))->put(Reference::of($right), Reference::of($top));

        $this->app?->instance(TenantTree::class, $tree);

        $chief  = Role::query()->withoutGlobalScopes()->create(['name' => 'chief', ...self::ownedBy($top)]);
        $beside = Role::query()->withoutGlobalScopes()->create(['name' => 'beside', ...self::ownedBy($right)]);
        $clerk  = Role::query()->withoutGlobalScopes()->create(['name' => 'clerk', ...self::ownedBy($left)]);
        $user   = StubIdentity::query()->create(['id' => 'user']);

        DB::table('roles')->where('id', $beside->id)->update(['parent_id' => $chief->id]);
        DB::table('roles')->where('id', $clerk->id)->update(['parent_id' => $beside->id]);

        self::insertGrant($clerk, $user, Reference::of($top), true);

        $holdings = ExclusionHoldings::read([$chief->id, $beside->id, $clerk->id], new TenantRelations);

        self::assertEquals(new GrantScope(Reference::of($left)), $holdings->of($clerk->id, Reference::of($user))[0]->reach);
        self::assertSame([], $holdings->of($beside->id, Reference::of($user)));
        self::assertSame([], $holdings->of($chief->id, Reference::of($user)));

        DB::table('roles')->where('id', $clerk->id)->update(['parent_id' => $chief->id]);

        $direct = ExclusionHoldings::read([$chief->id], new TenantRelations)->of($chief->id, Reference::of($user));

        self::assertSame([$clerk->id, $chief->id], self::pathOf($direct[0]->path));
        self::assertEquals(new GrantScope(Reference::of($left)), $direct[0]->reach);
        self::assertSame(0, $tree->reads);
    }

    /**
     * A role naming half a tenant ends the chain below it, so a grant of a role
     * below it holds neither it nor any role above it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleNamingHalfATenantEndsTheChain(): void
    {
        $chief  = Role::query()->create(['name' => 'chief']);
        $middle = Role::query()->create(['name' => 'middle', 'parent_id' => $chief->id]);
        $clerk  = Role::query()->create(['name' => 'clerk', 'parent_id' => $middle->id]);
        $user   = StubIdentity::query()->create(['id' => 'user']);

        self::grants()->grantRole($user, $clerk);

        DB::table('roles')->where('id', $middle->id)->update(['tenant_type' => 'stub_tenant']);

        $holdings = ExclusionHoldings::read([$chief->id, $middle->id, $clerk->id], new TenantRelations);

        self::assertSame([], $holdings->of($chief->id, Reference::of($user)));
        self::assertSame([], $holdings->of($middle->id, Reference::of($user)));
        self::assertSame([$clerk->id], self::pathOf($holdings->of($clerk->id, Reference::of($user))[0]->path));
    }

    /**
     * The roles below are read in the same number of queries however deep the
     * hierarchy below runs; with the hierarchy disabled they are never read,
     * and a grant holds its own role alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRolesBelowAreReadInAFixedNumberOfQueries(): void
    {
        $deep   = Role::query()->create(['name' => 'deep']);
        $flat   = Role::query()->create(['name' => 'flat']);
        $parent = $deep;

        foreach (\range(1, 5) as $depth) {
            $parent = Role::query()->create(['name' => 'below-' . $depth, 'parent_id' => $parent->id]);
        }

        $queries = static function (Role $role): int {
            $count = 0;

            DB::listen(static function () use (&$count): void {
                $count++;
            });

            ExclusionHoldings::read([$role->id], new TenantRelations);

            return $count;
        };

        self::assertSame($queries($flat), $queries($deep));

        config(['authorization.hierarchy.enabled' => false]);

        self::assertSame($queries($flat), $queries($deep));

        $user  = StubIdentity::query()->create(['id' => 'user']);
        $roles = [$deep->id, (string) $parent->parent_id, $parent->id];

        self::grants()->grantRole($user, $parent);

        $holdings = ExclusionHoldings::read($roles, new TenantRelations);
        $held     = \array_map(static fn (string $role): int => \count($holdings->of($role, Reference::of($user))), $roles);

        self::assertSame([0, 0, 1], $held);
    }

    /**
     * A chain that returns to a role it passed refuses the read, naming the
     * role granted and the role it returned to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACycleIsRefused(): void
    {
        $chief  = Role::query()->create(['name' => 'chief']);
        $clerk  = Role::query()->create(['name' => 'clerk', 'parent_id' => $chief->id]);
        $intern = Role::query()->create(['name' => 'intern', 'parent_id' => $clerk->id]);

        self::grants()->grantRole(StubIdentity::query()->create(['id' => 'user']), $intern);

        DB::table('roles')->where('id', $chief->id)->update(['parent_id' => $clerk->id]);

        try {
            ExclusionHoldings::read([$chief->id], new TenantRelations);

            self::fail('A cycle was read.');
        } catch (RoleHierarchyCycleException $exception) {
            self::assertSame(['intern', 'clerk'], [$exception->getRoleName(), $exception->getProposedParentName()]);
        }
    }

    /**
     * Read locked, the roles and the grants are read under shared locks, so
     * they are the rows as last committed; read plain, nothing is locked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockedReadLocksTheRolesAndGrantsItReads(): void
    {
        $clerk  = Role::query()->create(['name' => 'clerk']);
        $deputy = Role::query()->create(['name' => 'deputy', 'parent_id' => $clerk->id]);

        self::grants()->grantRole(StubIdentity::query()->create(['id' => 'user']), $deputy);

        self::assertSame([], $this->lockedTables(static fn (): ExclusionHoldings => ExclusionHoldings::read([$clerk->id], new TenantRelations)));
        $locked = $this->lockedTables(static fn (): ExclusionHoldings => ExclusionHoldings::read([$clerk->id], new TenantRelations, true));

        self::assertSame(['authorizable_roles', 'break_glass_activations', 'roles'], $locked);
    }

    /**
     * A live break-glass activation holds its role as a grant does, of a role
     * below too, and one proposed beside it; one ended, one expired and one
     * naming a machine hold nothing, and an identity's activations are left out
     * where it is weighed as another subject's identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALiveActivationHoldsItsRoleAsAGrantDoes(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $clerk   = Role::query()->create(['name' => 'clerk']);
        $deputy  = Role::query()->create(['name' => 'deputy', 'parent_id' => $clerk->id]);
        $user    = StubIdentity::query()->create(['id' => 'user']);
        $machine = StubMachine::query()->create(['id' => 'machine']);
        $tenant  = new Reference('stub_tenant', 'a');

        self::activate($deputy, Reference::of($user), $tenant, Carbon::now()->addHour());
        self::activate($clerk, Reference::of($user), null, Carbon::now()->addHour(), Carbon::now()->subMinute());
        self::activate($clerk, Reference::of($user), null, Carbon::now());
        self::activate($clerk, Reference::of($machine), null, Carbon::now()->addHour());

        $holdings = ExclusionHoldings::read([$clerk->id], new TenantRelations);
        $routes   = $holdings->of($clerk->id, Reference::of($user));

        self::assertCount(1, $routes);
        self::assertSame([$deputy->id, $clerk->id], self::pathOf($routes[0]->path));
        self::assertEquals($tenant, $routes[0]->scope->tenant);
        self::assertSame('2026-07-01 13:00:00', $routes[0]->expiresAt?->format('Y-m-d H:i:s'));
        self::assertSame([], $holdings->of($clerk->id, Reference::of($user), isIdentity: true));
        self::assertSame([], $holdings->of($clerk->id, Reference::of($machine)));
        self::assertCount(1, $holdings->holders($clerk->id));

        self::grants()->grantRole($user, $clerk);

        $proposed = ExclusionHoldings::read([$clerk->id], new TenantRelations, write: ExclusionWrite::proposed(Reference::of($machine), $clerk->id, new GrantScope($tenant)));

        self::assertCount(1, $proposed->of($clerk->id, Reference::of($user), isIdentity: true));
        self::assertCount(2, $proposed->of($clerk->id, Reference::of($user)));
        self::assertSame([], $proposed->of($clerk->id, Reference::of($machine)));

        Carbon::setTestNow();
    }

    /**
     * Return the keys of the roles of a path, in its order.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $path
     * @return list<string>
     */
    private static function pathOf(array $path): array
    {
        return \array_map(static fn (Reference $role): string => $role->id, $path);
    }

    /**
     * Store a break-glass activation of the role for the grantee, in the tenant
     * given or at the platform, until the expiry, ended at the instant given.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \DateTimeInterface  $expiresAt
     * @param  \DateTimeInterface|null  $endedAt
     * @return void
     */
    private static function activate(Role $role, Reference $grantee, ?Reference $tenant, \DateTimeInterface $expiresAt, ?\DateTimeInterface $endedAt = null): void
    {
        DB::table('break_glass_activations')->insert([
            'id'                => (string) Str::uuid(),
            'role_id'           => $role->id,
            'authorizable_type' => $grantee->type,
            'authorizable_id'   => $grantee->id,
            'tenant_type'       => $tenant?->type,
            'tenant_id'         => $tenant?->id,
            'include_subtree'   => true,
            'justification'     => 'incident',
            'activated_at'      => Carbon::now()->subHour(),
            'expires_at'        => $expiresAt,
            'ended_at'          => $endedAt,
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
     * @param  string|null  $application
     * @return void
     */
    private static function insertGrant(Role $role, StubIdentity $grantee, ?Reference $tenant, bool $includeSubtree, ?string $application = null): void
    {
        DB::table('authorizable_roles')->insert([
            'role_id'           => $role->id,
            'authorizable_type' => $grantee->getMorphClass(),
            'authorizable_id'   => $grantee->getKey(),
            'tenant_type'       => $tenant?->type,
            'tenant_id'         => $tenant?->id,
            'include_subtree'   => $includeSubtree,
            'application'       => $application,
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
