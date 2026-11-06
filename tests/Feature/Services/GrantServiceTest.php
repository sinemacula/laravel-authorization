<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyDetached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\GranteeGuardMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\InlinePolicyAttachmentException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\SyncResult;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\AssertsTransactions;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\ApiGuardedUser;
use Tests\Feature\Stubs\CustomPermission;
use Tests\Feature\Stubs\CustomRole;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `GrantService`, which grants, revokes and syncs roles,
 * permissions and policies to a grantee.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantService::class)]
#[CoversClass(SyncResult::class)]
final class GrantServiceTest extends TestCase
{
    use ActsAsTenant, AssertsTransactions, ComparesReferences, ReadsDispatchedEvents, UsesAnAuthorizationConnection;

    /** @var string The instant every test starts at. */
    private const string NOW = '2026-07-01 12:00:00';

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(self::NOW);
    }

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
     * The service is bound once in the container.
     *
     * @return void
     */
    public function testIsBoundAsASingleton(): void
    {
        self::assertSame(self::service(), self::service());
    }

    /**
     * Granting a role the grantee does not hold writes it and dispatches the
     * assigned event only.
     *
     * @return void
     */
    public function testGrantingARoleWritesItAndDispatchesTheAssignedEvent(): void
    {
        Event::fake();

        $user = self::user();
        $role = self::role('editor');

        self::assertSame(GrantOutcome::GRANTED, self::service()->grantRole($user, $role, Carbon::parse('2026-07-02 12:00:00', 'UTC')));
        self::assertSame(['editor'], $user->getRoles());
        Event::assertDispatchedTimes(RoleAssigned::class, 1);
        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => self::refersTo($event->grantee, $user) && self::refersTo($event->role, $role));
        Event::assertNotDispatched(RoleExpiryChanged::class);
    }

    /**
     * Granting what is held, with the same expiry, changes nothing and
     * dispatches nothing.
     *
     * @return void
     */
    public function testGrantingWhatIsHeldIsUnchangedAndDispatchesNothing(): void
    {
        $user = self::user();
        $role = self::role('editor');

        self::service()->grantRole($user, $role);

        Event::fake();

        self::assertSame(GrantOutcome::UNCHANGED, self::service()->grantRole($user, $role));
        self::assertSame(GrantOutcome::UNCHANGED, self::service()->grantRole($user, 'editor'));
        self::assertNoGrantEvents();
    }

    /**
     * A duplicate another transaction writes between the lookup and the insert
     * is reported as unchanged, dispatches nothing and never surfaces a
     * unique-constraint violation.
     *
     * @return void
     */
    public function testAConcurrentDuplicateIsUnchanged(): void
    {
        $user    = self::user();
        $role    = self::role('editor');
        $written = false;

        DB::listen(static function (QueryExecuted $query) use (&$written, $role, $user): void {
            if ($written || \str_contains($query->sql, 'authorizable_roles')) {
                return;
            }

            $written = true;

            DB::table('authorizable_roles')->insert([
                'role_id'           => $role->id,
                'authorizable_type' => $user->getMorphClass(),
                'authorizable_id'   => 'user-1',
            ]);
        });

        Event::fake();

        self::assertSame(GrantOutcome::UNCHANGED, self::service()->grantRole($user, 'editor'));
        self::assertSame(1, DB::table('authorizable_roles')->count());
        self::assertNoGrantEvents();
    }

    /**
     * Changing a live grant's expiry is a change: the assigned and the
     * expiry-changed events are dispatched, with both expiries.
     *
     * @return void
     */
    public function testChangingAnExpiryIsReportedAsAChange(): void
    {
        $user   = self::user();
        $role   = self::role('editor');
        $before = Carbon::parse('2026-07-02 12:00:00', 'UTC');
        $after  = Carbon::parse('2026-07-03 12:00:00', 'UTC');

        self::service()->grantRole($user, $role, $before);

        Event::fake();

        self::assertSame(GrantOutcome::EXPIRY_CHANGED, self::service()->grantRole($user, $role, $after));
        Event::assertDispatchedTimes(RoleAssigned::class, 1);
        Event::assertDispatched(RoleExpiryChanged::class, static fn (RoleExpiryChanged $event): bool => self::refersTo($event->grantee, $user)
            && self::refersTo($event->role, $role)
            && $event->previousExpiresAt?->getTimestamp() === $before->getTimestamp()
            && $event->expiresAt?->getTimestamp()         === $after->getTimestamp());
    }

    /**
     * Granting again a role whose grant has expired re-arms it with the new
     * expiry, so the grantee holds it again.
     *
     * @return void
     */
    public function testRegrantingAnExpiredRoleReArmsIt(): void
    {
        $user = self::user();
        $role = self::role('editor');

        self::service()->grantRole($user, $role, Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        Carbon::setTestNow('2026-07-01 14:00:00');

        self::assertSame([], self::heldRoleNames($user));

        Event::fake();

        self::assertSame(GrantOutcome::REARMED, self::service()->grantRole($user, $role, Carbon::parse('2026-07-02 14:00:00', 'UTC')));
        self::assertSame(['editor'], self::heldRoleNames($user));
        Event::assertDispatchedTimes(RoleAssigned::class, 1);
        Event::assertDispatchedTimes(RoleExpiryChanged::class, 1);
    }

    /**
     * A grant clears the grantee's loaded relation, so the next read sees it.
     *
     * @return void
     */
    public function testAGrantClearsTheLoadedRelation(): void
    {
        $user = self::user();

        self::assertCount(0, $user->roles);

        self::service()->grantRole($user, self::role('editor'));

        self::assertFalse($user->relationLoaded('roles'));
    }

    /**
     * A grant is written platform-wide, for every application, on the package's
     * connection.
     *
     * @return void
     */
    public function testGrantsArePlatformWideOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();

        $user = self::user();
        $role = self::role('editor');

        self::service()->grantRole($user, $role);

        $row = self::authorizationConnection()->table('authorizable_roles')->sole();

        self::assertSame($role->id, $row->role_id);
        self::assertNull($row->tenant_type);
        self::assertNull($row->tenant_id);
        self::assertNull($row->application);
        self::assertSame(0, DB::table('authorizable_roles')->count());
    }

    /**
     * Revoking everything removes every role, permission and policy the grantee
     * holds, in one operation that reports each revocation with the actor, and
     * leaves other grantees' grants alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingEverythingRemovesEveryGrant(): void
    {
        $user   = self::user();
        $other  = StubIdentity::create(['id' => 'user-2']);
        $role   = Role::create(['name' => 'editor']);
        $policy = Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);
        $actor  = new Reference('admin', 'admin-1');

        self::service()->grantRole($user, $role);
        self::service()->grantRole($other, $role);
        self::service()->grantPermission($user, Permission::create(['name' => 'posts:edit']));
        self::service()->attachPolicy($user, $policy);

        Event::fake();

        self::assertSame(3, self::service()->revokeAll($user, $actor));

        self::assertSame(0, DB::table('authorizable_roles')->where('authorizable_id', $user->getKey())->count());
        self::assertSame(0, DB::table('authorizable_permissions')->where('authorizable_id', $user->getKey())->count());
        self::assertSame(0, DB::table('authorizable_policies')->where('authorizable_id', $user->getKey())->count());
        self::assertSame(1, DB::table('authorizable_roles')->where('authorizable_id', 'user-2')->count());

        Event::assertDispatched(
            RoleRevoked::class,
            static fn (RoleRevoked $event): bool => self::refersTo($event->grantee, $user) && self::refersTo($event->operation->actor, $actor),
        );
        Event::assertDispatched(PermissionRevoked::class, static fn (PermissionRevoked $event): bool => self::refersTo($event->grantee, $user));
        Event::assertDispatched(PolicyDetached::class, static fn (PolicyDetached $event): bool => self::refersTo($event->grantee, $user));

        $events     = [...self::dispatchedEvents(RoleRevoked::class), ...self::dispatchedEvents(PermissionRevoked::class), ...self::dispatchedEvents(PolicyDetached::class)];
        $operations = \array_unique(\array_map(static fn (PermissionRevoked|PolicyDetached|RoleRevoked $event): string => $event->operation->id, $events));

        self::assertCount(1, $operations);
        self::assertSame([], $user->getRoles());
        self::assertSame(0, self::service()->revokeAll($user));
    }

    /**
     * A grant in a tenant can be limited to it, and granting it again with the
     * other reach changes the reach, reported as a change with the granted
     * event carrying it; a platform-wide grant always reaches below, whatever
     * it is given, each kind and the trait helpers pass the reach on, and each
     * reaches below by default.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantInATenantCanBeLimitedToIt(): void
    {
        $user   = self::user();
        $tenant = Reference::of(self::createTenant('tenant-a'));

        Role::query()->create(['name' => 'editor']);
        Role::query()->create(['name' => 'viewer']);
        Permission::query()->create(['name' => 'posts:edit']);
        Policy::query()->create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);

        Event::fake();

        $outcomes = [
            self::service()->grantRole($user, 'editor', tenant: $tenant, includeSubtree: false),
            self::service()->grantRole($user, 'editor', tenant: $tenant),
            self::service()->grantRole($user, 'editor', tenant: $tenant),
            self::service()->grantRole($user, 'viewer', includeSubtree: false),
            self::service()->grantRole($user, 'viewer'),
        ];

        self::assertSame([GrantOutcome::GRANTED, GrantOutcome::REACH_CHANGED, GrantOutcome::UNCHANGED, GrantOutcome::GRANTED, GrantOutcome::UNCHANGED], $outcomes);

        $user->givePermission('posts:edit', null, $tenant, false);
        $user->attachPolicy(Policy::query()->sole(), null, $tenant, false);
        $user->assignRole('viewer', null, $tenant, false);

        self::assertSame(
            [false, true, true],
            \array_map(static fn (RoleAssigned $event): bool => $event->scope->includeSubtree, \array_slice(self::dispatchedEvents(RoleAssigned::class), 0, 3)),
        );
        self::assertFalse(self::dispatchedEvents(RoleAssigned::class)[3]->scope->includeSubtree);
        self::assertFalse(self::dispatchedEvents(PermissionGranted::class)[0]->scope->includeSubtree);
        self::assertFalse(self::dispatchedEvents(PolicyAttached::class)[0]->scope->includeSubtree);
        self::assertSame(0, DB::table('authorizable_roles')->whereNull('tenant_type')->where('include_subtree', false)->count());
        self::assertSame(1, DB::table('authorizable_permissions')->where('include_subtree', false)->count());
        self::assertSame(1, DB::table('authorizable_policies')->where('include_subtree', false)->count());
        self::assertSame(GrantOutcome::REACH_CHANGED, self::service()->grantPermission($user, 'posts:edit', tenant: $tenant));
        self::assertSame(GrantOutcome::REACH_CHANGED, self::service()->attachPolicy($user, Policy::query()->sole(), tenant: $tenant));
        self::assertSame(0, DB::table('authorizable_permissions')->where('include_subtree', false)->count());
        self::assertSame(0, DB::table('authorizable_policies')->where('include_subtree', false)->count());
    }

    /**
     * A revocation reports the reach the grant had, whether it is revoked by
     * itself, dropped by a sync or revoked with everything the grantee held.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationReportsTheReachTheGrantHad(): void
    {
        $user   = self::user();
        $tenant = Reference::of(self::createTenant('tenant-a'));

        foreach (['editor', 'viewer', 'author', 'owner'] as $name) {
            Role::query()->create(['name' => $name]);
        }

        self::service()->grantRole($user, 'editor', tenant: $tenant, includeSubtree: false);
        self::service()->grantRole($user, 'viewer', tenant: $tenant, includeSubtree: false);
        self::service()->grantRole($user, 'author', tenant: $tenant);
        self::service()->grantRole($user, 'owner', tenant: $tenant, includeSubtree: false);

        Event::fake();

        self::service()->revokeRole($user, 'editor', tenant: $tenant);
        self::service()->syncRoles($user, ['author', 'owner'], tenant: $tenant);
        self::service()->revokeAll($user);

        $reaches = [];

        foreach (self::dispatchedEvents(RoleRevoked::class) as $event) {
            $reaches[$event->name] = $event->scope->includeSubtree;
        }

        self::assertEquals(['editor' => false, 'viewer' => false, 'author' => true, 'owner' => false], $reaches);
    }

    /**
     * A grant can be made for one application, apart from the grant for every
     * application, and each kind's grant, revocation and sync stays in the
     * application named, every event reporting it (D24).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantCanBeMadeForOneApplication(): void
    {
        $user   = self::user();
        $policy = Policy::query()->create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);

        Role::query()->create(['name' => 'editor']);
        Permission::query()->create(['name' => 'posts:edit']);

        Event::fake();

        $outcomes = [
            self::service()->grantRole($user, 'editor', application: 'admin'),
            self::service()->grantRole($user, 'editor'),
            self::service()->grantRole($user, 'editor', application: 'admin'),
            self::service()->grantPermission($user, 'posts:edit', application: 'admin'),
            self::service()->attachPolicy($user, $policy, application: 'admin'),
        ];

        $applications = \array_map(static fn (RoleAssigned $event): ?string => $event->scope->application, self::dispatchedEvents(RoleAssigned::class));

        self::assertSame([GrantOutcome::GRANTED, GrantOutcome::GRANTED, GrantOutcome::UNCHANGED, GrantOutcome::GRANTED, GrantOutcome::GRANTED], $outcomes);
        self::assertSame(['admin', null], $applications);
        self::assertSame('admin', self::dispatchedEvents(PermissionGranted::class)[0]->scope->application);
        self::assertSame('admin', self::dispatchedEvents(PolicyAttached::class)[0]->scope->application);

        self::assertSame(0, self::service()->revokePermission($user, 'posts:edit', application: 'mobile'));
        self::assertSame(1, self::service()->revokeRole($user, 'editor', application: 'admin'));
        self::assertSame(1, self::service()->detachPolicy($user, $policy, application: 'admin'));
        self::assertSame('admin', self::dispatchedEvents(RoleRevoked::class)[0]->scope->application);
        self::assertSame([null], DB::table('authorizable_roles')->pluck('application')->all());

        self::assertCount(1, self::service()->syncRoles($user, ['editor'], application: 'mobile')->granted);
        self::assertCount(1, self::service()->syncPermissions($user, [], application: 'admin')->revoked);
        self::assertCount(1, self::service()->syncPolicies($user, [$policy], application: 'mobile')->granted);
        self::assertEqualsCanonicalizing([null, 'mobile'], DB::table('authorizable_roles')->pluck('application')->all());
        self::assertSame(0, DB::table('authorizable_permissions')->count());
        self::assertSame(['mobile'], DB::table('authorizable_policies')->pluck('application')->all());

        self::service()->revokeAll($user);

        $revoked = \array_map(static fn (RoleRevoked $event): ?string => $event->scope->application, self::dispatchedEvents(RoleRevoked::class));

        self::assertEqualsCanonicalizing([null, 'mobile', 'admin'], $revoked);
    }

    /**
     * A sync in a named tenant works there, not in the tenant its targets
     * share, so a target that other tenant owns is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncInANamedTenantRefusesATargetOwnedByAnother(): void
    {
        $user  = self::user();
        $owner = self::createTenant('tenant-a');

        Role::query()->create(['name' => 'editor', ...self::ownedBy($owner)]);

        $this->expectException(GrantScopeMismatchException::class);

        self::service()->syncRoles($user, [Role::query()->withoutGlobalScopes()->sole()], tenant: Reference::of(self::createTenant('tenant-b')));
    }

    /**
     * A sync writes its reach to what it grants and re-arms, reporting each,
     * and leaves a live grant it keeps as it is; by default it reaches below.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncWritesItsReachOnlyToWhatItGrants(): void
    {
        $user   = self::user();
        $tenant = Reference::of(self::createTenant('tenant-a'));

        foreach (['editor', 'viewer', 'author'] as $name) {
            Role::query()->create(['name' => $name]);
        }

        Permission::query()->create(['name' => 'posts:edit']);
        Policy::query()->create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);

        self::service()->grantRole($user, 'editor', tenant: $tenant);
        self::service()->grantRole($user, 'viewer', Carbon::parse('2000-01-01 00:00:00'), tenant: $tenant);

        Event::fake();

        $result = self::service()->syncRoles($user, ['editor', 'viewer', 'author'], tenant: $tenant, includeSubtree: false);

        self::assertEqualsCanonicalizing(['viewer', 'author'], \array_map(static fn (RoleAssigned $event): string => $event->name, self::dispatchedEvents(RoleAssigned::class)));

        self::service()->syncPermissions($user, ['posts:edit'], tenant: $tenant, includeSubtree: false);
        self::service()->syncPolicies($user, [Policy::query()->sole()], tenant: $tenant, includeSubtree: false);

        $reaches = DB::table('authorizable_roles')
            ->join('roles', 'roles.id', '=', 'authorizable_roles.role_id')
            ->pluck('authorizable_roles.include_subtree', 'roles.name')
            ->map(static fn (mixed $reach): bool => (bool) $reach)
            ->all();

        self::assertCount(1, $result->granted);
        self::assertCount(1, $result->rearmed);
        self::assertEquals(['editor' => true, 'viewer' => false, 'author' => false], $reaches);
        self::assertSame(1, DB::table('authorizable_permissions')->where('include_subtree', false)->count());
        self::assertSame(1, DB::table('authorizable_policies')->where('include_subtree', false)->count());

        $other = StubIdentity::query()->create(['id' => 'user-2']);

        self::service()->syncRoles($other, ['editor'], tenant: $tenant);
        self::service()->syncPermissions($other, ['posts:edit'], tenant: $tenant);
        self::service()->syncPolicies($other, [Policy::query()->sole()], tenant: $tenant);

        foreach (['authorizable_roles', 'authorizable_permissions', 'authorizable_policies'] as $table) {
            self::assertTrue((bool) DB::table($table)->where('authorizable_id', 'user-2')->value('include_subtree'), "{$table} did not reach below by default.");
        }
    }

    /**
     * A role a tenant owns is granted in that tenant without naming it, and the
     * event reports the scope; naming another tenant is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOwnedRoleIsGrantedInItsTenant(): void
    {
        $user   = self::user();
        $tenant = self::createTenant('tenant-a');
        $role   = Role::query()->create(['name' => 'editor', ...self::ownedBy($tenant)]);

        Event::fake();

        self::service()->grantRole($user, $role);

        $scopes = DB::table('authorizable_roles')->get(['tenant_type', 'tenant_id'])->map(static fn (object $row): array => [$row->tenant_type, $row->tenant_id]);

        self::assertSame([[$tenant->getMorphClass(), 'tenant-a']], $scopes->all());
        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => self::refersTo($event->scope->tenant, $tenant));

        try {
            self::service()->grantRole($user, $role, null, null, self::createTenant('tenant-b'));
            self::fail('A role granted outside its tenant was not refused.');
        } catch (GrantScopeMismatchException $exception) {
            self::assertSame('role', $exception->getKind());
            self::assertSame('editor', $exception->getName());
            self::assertTrue(self::refersTo($exception->getOwner(), $tenant));
            self::assertSame('tenant-b', $exception->getScope()?->id);
        }

        self::assertSame(1, DB::table('authorizable_roles')->count());
    }

    /**
     * A platform role is granted platform-wide unless a tenant is named, and in
     * that tenant when one is; the same role may be held in both.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformRoleIsGrantedWhereTheCallerNames(): void
    {
        $user   = self::user();
        $tenant = self::createTenant('tenant-a');
        $role   = self::role('editor');

        self::service()->grantRole($user, $role);
        self::service()->grantRole($user, $role, null, null, $tenant);

        self::assertEqualsCanonicalizing([null, 'tenant-a'], DB::table('authorizable_roles')->pluck('tenant_id')->all());
    }

    /**
     * A name is looked up among the rows visible in the tenant named, not the
     * current tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANameIsLookedUpInTheTenantNamed(): void
    {
        $user    = self::user();
        $tenantA = self::createTenant('tenant-a');
        $owned   = Role::query()->create(['name' => 'editor', ...self::ownedBy($tenantA)]);

        self::role('editor');
        $this->actAsTenant(self::createTenant('tenant-b'));

        self::service()->grantRole($user, 'editor', null, null, $tenantA);

        self::assertSame([$owned->id], DB::table('authorizable_roles')->pluck('role_id')->all());
        self::assertSame(1, self::service()->revokeRole($user, 'editor', null, $tenantA));
    }

    /**
     * A sync with no tenant named works in the tenant that owns every target,
     * and is refused when the targets are owned by different tenants or mix a
     * tenant's role with the platform's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncWorksInTheTenantItsTargetsShare(): void
    {
        $user     = self::user();
        $tenant   = self::createTenant('tenant-a');
        $editor   = Role::query()->create(['name' => 'editor', ...self::ownedBy($tenant)]);
        $author   = Role::query()->create(['name' => 'author', ...self::ownedBy($tenant)]);
        $platform = self::role('viewer');
        $other    = Role::query()->create(['name' => 'owner', ...self::ownedBy(self::createTenant('tenant-b'))]);

        self::assertSame([$editor->id, $author->id], self::service()->syncRoles($user, [$editor, $author])->granted);
        self::assertSame(['tenant-a', 'tenant-a'], DB::table('authorizable_roles')->pluck('tenant_id')->all());

        foreach ([[$editor, $platform], [$editor, $other]] as $targets) {
            try {
                self::service()->syncRoles($user, $targets);
                self::fail('A sync across scopes was not refused.');
            } catch (GrantScopeMismatchException $exception) {
                self::assertSame('role', $exception->getKind());
            }
        }

        self::assertSame(2, DB::table('authorizable_roles')->count());
    }

    /**
     * Revoking everything reports each grant in the scope it was held in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingEverythingReportsEachScope(): void
    {
        $user   = self::user();
        $tenant = self::createTenant('tenant-a');
        $role   = self::role('editor');

        self::service()->grantRole($user, $role);
        self::service()->grantRole($user, $role, null, null, $tenant);

        Event::fake();

        self::assertSame(2, self::service()->revokeAll($user));
        Event::assertDispatchedTimes(RoleRevoked::class, 2);
        Event::assertDispatched(RoleRevoked::class, static fn (RoleRevoked $event): bool => $event->scope->tenant === null);
        Event::assertDispatched(RoleRevoked::class, static fn (RoleRevoked $event): bool => self::refersTo($event->scope->tenant, $tenant));
    }

    /**
     * A role or permission of another guard than the grantee declares is
     * refused, in a grant and in a sync.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantMustSuitTheGranteesGuard(): void
    {
        $user = ApiGuardedUser::query()->create(['id' => 'api-user']);
        $role = Role::query()->create(['name' => 'editor', 'guard' => 'web']);

        foreach ([static fn () => self::service()->grantRole($user, $role), static fn () => self::service()->syncRoles($user, [$role])] as $write) {
            try {
                $write();
                self::fail('A role of another guard was granted.');
            } catch (GranteeGuardMismatchException $exception) {
                self::assertSame('api', $exception->getGranteeGuard());
            }
        }

        self::assertSame(0, DB::table('authorizable_roles')->count());
    }

    /**
     * Each call runs in a transaction on the package's connection.
     *
     * @return void
     */
    public function testRunsInATransactionOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();

        $levels = [];

        DB::listen(static function (QueryExecuted $query) use (&$levels): void {
            if (!\str_contains($query->sql, 'authorizable_roles')) {
                return;
            }

            $levels[] = [$query->connectionName, $query->connection->transactionLevel()];
        });

        self::service()->grantRole(self::user(), self::role('editor'));

        self::assertNotSame([], $levels);

        foreach ($levels as [$connection, $level]) {
            self::assertSame('authorization', $connection);
            self::assertGreaterThan(0, $level);
        }
    }

    /**
     * Each revocation runs in one transaction on the package's connection: the
     * lookups as well as the delete.
     *
     * @return void
     */
    public function testRevocationsRunInATransactionOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();

        $user   = self::user();
        $policy = self::policy('audit');

        self::role('editor');
        Permission::query()->create(['name' => 'posts:edit']);

        self::service()->grantRole($user, 'editor');
        self::service()->grantPermission($user, 'posts:edit');
        self::service()->attachPolicy($user, $policy);

        self::assertSame(1, self::assertAllInATransaction(static fn (): int => self::service()->revokeRole($user, 'editor')));
        self::assertSame(1, self::assertAllInATransaction(static fn (): int => self::service()->revokePermission($user, 'posts:edit')));
        self::assertSame(1, self::assertAllInATransaction(static fn (): int => self::service()->detachPolicy($user, $policy)));
    }

    /**
     * A sync that fails part-way rolls back what it wrote before the failure:
     * the revoked grant is back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncThatFailsPartWayRollsBack(): void
    {
        $user   = self::user();
        $kept   = self::role('kept');
        $listed = self::role('listed');

        self::service()->grantRole($user, $kept);

        DB::listen(static function (QueryExecuted $query): void {
            if (!\str_starts_with(\strtolower($query->sql), 'insert') || !\str_contains($query->sql, 'authorizable_roles')) {
                return;
            }

            throw new \RuntimeException('Write failed.');
        });

        try {
            self::service()->syncRoles($user, [$listed]);
            self::fail('The sync did not fail.');
        } catch (\RuntimeException $exception) {
            self::assertSame('Write failed.', $exception->getMessage());
        }

        self::assertSame([$kept->id], DB::table('authorizable_roles')->pluck('role_id')->all());
    }

    /**
     * A name is looked up under the grantee's own guard.
     *
     * @return void
     */
    public function testANameIsLookedUpUnderTheGranteesGuard(): void
    {
        self::role('editor');
        $api  = Role::query()->create(['name' => 'editor', 'guard' => 'api']);
        $user = ApiGuardedUser::query()->create(['id' => 'api-user']);

        self::service()->grantRole($user, 'editor');

        self::assertSame([$api->id], DB::table('authorizable_roles')->where('authorizable_id', 'api-user')->pluck('role_id')->all());
    }

    /**
     * A guard hook that names no guard leaves the lookup to the package
     * default.
     *
     * @return void
     */
    public function testAGuardHookThatNamesNoGuardFallsBackToTheDefault(): void
    {
        Role::query()->create(['name' => 'editor', 'guard' => 'api']);
        $web = Role::query()->create(['name' => 'editor', 'guard' => 'web']);

        $grantee = new class (['id' => 'hooked']) extends Model {
            /** @var bool Whether the key increments. */
            public $incrementing = false;

            /** @var string The key's type. */
            protected $keyType = 'string';

            /** @var list<string> Attributes that are mass assignable. */
            protected $fillable = ['id'];

            /**
             * Name no guard.
             *
             * A test double answering the package contract, not model
             * behaviour.
             *
             * @return null
             *
             * @phpstan-ignore sineMaculaLaravel.modelBehaviour
             */
            public function getAuthorizationGuard(): null
            {
                return null;
            }
        };

        $grantee->exists = true;

        // An anonymous class's name runs past the 191 bytes a reference holds,
        // so the grantee is named through the morph map.
        Relation::morphMap(['hooked-user' => $grantee::class]);

        try {
            self::service()->grantRole($grantee, 'editor');
        } finally {
            Relation::morphMap([], false);
        }

        self::assertSame([$web->id], DB::table('authorizable_roles')->where('authorizable_id', 'hooked')->pluck('role_id')->all());
    }

    /**
     * Grantees a grant cannot be written for: an unsaved model, a saved model
     * with an empty key, and a reference with an empty type or key.
     *
     * @return iterable<string, array{\Closure(): (\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference), string}>
     */
    public static function invalidGrantees(): iterable
    {
        yield 'an unsaved model' => [static fn (): StubIdentity => new StubIdentity(['name' => 'x']), 'an unsaved ' . StubIdentity::class];
        yield 'an unsaved model with a key' => [static fn (): StubIdentity => new StubIdentity(['id' => 'user-1']), 'an unsaved ' . StubIdentity::class];
        yield 'a saved model with an empty key' => [static function (): StubIdentity {
            $identity         = new StubIdentity(['id' => '']);
            $identity->exists = true;

            return $identity;
        }, 'an incomplete ' . StubIdentity::class];
        yield 'a reference with an empty key' => [static fn (): Reference => new Reference('App\Models\User', ''), 'an incomplete ' . Reference::class];
        yield 'a reference with an empty type' => [static fn (): Reference => new Reference('', '42'), 'an incomplete ' . Reference::class];
    }

    /**
     * A grant, revocation or sync for a grantee a grant cannot be written for
     * is refused before anything is read or written, and dispatches nothing.
     *
     * @param  \Closure(): (\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference)  $grantee
     * @param  string  $described
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('invalidGrantees')]
    public function testRefusesAGranteeAGrantCannotBeWrittenFor(\Closure $grantee, string $described): void
    {
        $role    = self::role('editor');
        $queries = 0;

        Event::fake();

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $calls = [
            'grant'  => static fn (GrantService $service): mixed => $service->grantRole($grantee(), $role),
            'revoke' => static fn (GrantService $service): mixed => $service->revokeRole($grantee(), 'editor'),
            'sync'   => static fn (GrantService $service): mixed => $service->syncRoles($grantee(), [$role]),
        ];

        foreach ($calls as $name => $call) {
            try {
                $call(self::service());
                self::fail("The {$name} was not refused.");
            } catch (InvalidGranteeException $exception) {
                self::assertSame("A grant takes a saved grantee with a type and a key, not {$described}.", $exception->getMessage());
            }
        }

        self::assertSame(0, $queries);
        self::assertSame(0, DB::table('authorizable_roles')->count());
        self::assertNoGrantEvents();
    }

    /**
     * A name is looked up through the configured role class.
     *
     * @return void
     */
    public function testANameIsLookedUpThroughTheConfiguredClass(): void
    {
        $this->config()->set('authorization.models.role', CustomRole::class);

        self::role('editor');

        Event::fake();

        self::service()->grantRole(self::user(), 'editor');

        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => $event->role->type === (new CustomRole)->getMorphClass());
    }

    /**
     * An unknown name throws and writes nothing.
     *
     * @return void
     */
    public function testAnUnknownNameThrows(): void
    {
        $this->expectExceptionObject(new UnknownRoleException('ghost'));

        self::service()->grantRole(self::user(), 'ghost');
    }

    /**
     * A grantee named by a reference is granted without loading it, and the
     * events carry the reference.
     *
     * @return void
     */
    public function testGrantsToAReference(): void
    {
        Event::fake();

        $grantee = new Reference('App\Models\User', '42');
        $role    = self::role('editor');

        self::service()->grantRole($grantee, $role);

        $row = DB::table('authorizable_roles')->sole();

        self::assertSame('App\Models\User', $row->authorizable_type);
        self::assertSame('42', $row->authorizable_id);
        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => self::refersTo($event->grantee, $grantee));
    }

    /**
     * Revoking a held role deletes it and dispatches the revoked event.
     *
     * @return void
     */
    public function testRevokingAHeldRoleDispatchesTheRevokedEvent(): void
    {
        $user = self::user();
        $role = self::role('editor');

        self::service()->grantRole($user, $role);

        Event::fake();

        self::assertSame(1, self::service()->revokeRole($user, $role));
        self::assertSame(0, DB::table('authorizable_roles')->count());
        Event::assertDispatched(RoleRevoked::class, static fn (RoleRevoked $event): bool => self::refersTo($event->grantee, $user) && self::refersTo($event->role, $role));
    }

    /**
     * Revoking what is not held changes nothing and dispatches nothing.
     *
     * @return void
     */
    public function testRevokingWhatIsNotHeldDispatchesNothing(): void
    {
        $user = self::user();
        $role = self::role('editor');

        Event::fake();

        self::assertSame(0, self::service()->revokeRole($user, $role));
        self::assertSame(0, self::service()->revokeRole($user, 'editor'));
        self::assertNoGrantEvents();
    }

    /**
     * Revoking a name revokes every held role of that name, once each.
     *
     * @return void
     */
    public function testRevokingANameRevokesEveryHeldRoleOfIt(): void
    {
        $user    = self::user();
        $tenant  = self::createTenant('tenant-a');
        $global  = self::role('editor');
        $scoped  = Role::query()->create(['name' => 'editor', ...self::ownedBy($tenant)]);
        $another = self::role('viewer');

        $this->actAsTenant($tenant);

        self::service()->grantRole($user, $global);
        self::service()->grantRole($user, $scoped);
        self::service()->grantRole($user, $another);

        Event::fake();

        self::assertSame(2, self::service()->revokeRole($user, 'editor'));
        self::assertSame([$another->id], DB::table('authorizable_roles')->pluck('role_id')->all());
        Event::assertDispatchedTimes(RoleRevoked::class, 2);
    }

    /**
     * Revoking a role removes its grant in one scope: platform-wide unless a
     * tenant is named, so a grant in a tenant stays until it is revoked there.
     *
     * @return void
     */
    public function testRevokingRemovesTheRoleInOneScope(): void
    {
        $user   = self::user();
        $role   = self::role('editor');
        $tenant = new Reference('stub_tenant', 'tenant-a');

        self::service()->grantRole($user, $role);
        self::service()->grantRole($user, $role, null, null, $tenant);

        self::assertSame(1, self::service()->revokeRole($user, $role));
        self::assertSame(['tenant-a'], DB::table('authorizable_roles')->pluck('tenant_id')->all());
        self::assertSame(0, self::service()->revokeRole($user, $role));
        self::assertSame(1, self::service()->revokeRole($user, $role, null, $tenant));
        self::assertSame(0, DB::table('authorizable_roles')->count());
    }

    /**
     * Revoking a role clears the loaded relation.
     *
     * @return void
     */
    public function testRevokingClearsTheLoadedRelation(): void
    {
        $user = self::user();

        self::service()->grantRole($user, self::role('editor'));

        self::assertCount(1, $user->roles);

        self::service()->revokeRole($user, 'editor');

        self::assertFalse($user->relationLoaded('roles'));
    }

    /**
     * A sync grants what is missing, revokes what is not listed, keeps what is
     * live and reports each, dispatching one event per change.
     *
     * @return void
     */
    public function testASyncGrantsRevokesAndKeeps(): void
    {
        $user   = self::user();
        $kept   = self::role('kept');
        $gone   = self::role('gone');
        $joined = self::role('joined');

        self::service()->grantRole($user, $kept, Carbon::parse('2026-07-02 12:00:00', 'UTC'));
        self::service()->grantRole($user, $gone);

        Event::fake();

        $result = self::service()->syncRoles($user, [$kept, 'joined'], Carbon::parse('2026-08-01 12:00:00', 'UTC'));

        self::assertSame([$joined->id], $result->granted);
        self::assertSame([], $result->rearmed);
        self::assertSame([$gone->id], $result->revoked);
        self::assertTrue($result->isChange());
        $expected = [$kept->id => '2026-07-02 12:00:00', $joined->id => '2026-08-01 12:00:00'];

        \ksort($expected);

        self::assertSame($expected, self::expiries());
        Event::assertDispatchedTimes(RoleAssigned::class, 1);
        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => self::refersTo($event->role, $joined));
        Event::assertDispatched(RoleRevoked::class, static fn (RoleRevoked $event): bool => self::refersTo($event->grantee, $user) && self::refersTo($event->role, $gone));
        Event::assertDispatchedTimes(RoleRevoked::class, 1);
    }

    /**
     * A sync of what is held changes nothing and dispatches nothing.
     *
     * @return void
     */
    public function testASyncOfWhatIsHeldDispatchesNothing(): void
    {
        $user = self::user();
        $role = self::role('editor');

        self::service()->grantRole($user, $role);

        Event::fake();

        $result = self::service()->syncRoles($user, [$role]);

        self::assertFalse($result->isChange());
        self::assertNoGrantEvents();
    }

    /**
     * A sync re-arms a listed role whose grant has expired, rather than keeping
     * it expired.
     *
     * @return void
     */
    public function testASyncReArmsAnExpiredGrant(): void
    {
        $user = self::user();
        $role = self::role('editor');

        self::service()->grantRole($user, $role, Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        Carbon::setTestNow('2026-07-01 14:00:00');

        Event::fake();

        $result = self::service()->syncRoles($user, ['editor']);

        self::assertSame([$role->id], $result->rearmed);
        self::assertSame([], $result->granted);
        self::assertNull(DB::table('authorizable_roles')->value('expires_at'));
        self::assertSame(['editor'], self::heldRoleNames($user));
        Event::assertDispatchedTimes(RoleAssigned::class, 1);
        Event::assertDispatchedTimes(RoleExpiryChanged::class, 1);
    }

    /**
     * A name in a sync keeps every role of that name held in the sync's scope,
     * and only when none is held is the first the lookup ranks there granted.
     *
     * @return void
     */
    public function testASyncNameKeepsTheHeldRolesOfIt(): void
    {
        $user   = self::user();
        $tenant = self::createTenant('tenant-a');
        $global = self::role('editor');
        $scoped = Role::query()->create(['name' => 'editor', ...self::ownedBy($tenant)]);

        self::service()->grantRole($user, $global, null, null, $tenant);

        $result = self::service()->syncRoles($user, ['editor'], null, null, $tenant);

        self::assertFalse($result->isChange());
        self::assertSame([$global->id], DB::table('authorizable_roles')->pluck('role_id')->all());

        self::service()->syncRoles($user, [], null, null, $tenant);

        self::assertSame([$scoped->id], self::service()->syncRoles($user, ['editor'], null, null, $tenant)->granted);
    }

    /**
     * A sync replaces the grants of one scope: one with no tenant named leaves
     * a grant in another tenant, and one in that tenant reports it revoked,
     * though another tenant is current.
     *
     * @return void
     */
    public function testASyncReportsARevokedRoleOfAnotherTenant(): void
    {
        $user   = self::user();
        $tenant = self::createTenant('tenant-a');
        $other  = Role::query()->create(['name' => 'editor', ...self::ownedBy($tenant)]);

        self::service()->grantRole($user, $other);

        $this->actAsTenant(self::createTenant('tenant-b'));

        Event::fake();

        self::assertSame([], self::service()->syncRoles($user, [])->revoked);
        self::assertSame([$other->id], self::service()->syncRoles($user, [], null, null, $tenant)->revoked);
        Event::assertDispatched(RoleRevoked::class, static fn (RoleRevoked $event): bool => self::refersTo($event->role, $other) && self::refersTo($event->scope->tenant, $tenant));
    }

    /**
     * A sync refuses an entry of another kind and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncRefusesAnEntryOfAnotherKind(): void
    {
        $user = self::user();
        $role = self::role('editor');

        self::service()->grantRole($user, $role);

        $permission = Permission::query()->create(['name' => 'posts:edit']);

        try {
            self::service()->syncRoles($user, [$permission]); // @phpstan-ignore argument.type
            self::fail('The sync was not refused.');
        } catch (InvalidGrantTargetException $exception) {
            self::assertSame('role', $exception->getKind());
        }

        self::assertSame([$role->id], DB::table('authorizable_roles')->pluck('role_id')->all());
    }

    /**
     * A policy sync refuses anything that is not a saved policy, a name
     * included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicySyncRefusesAnythingButAPolicy(): void
    {
        $user = self::user();

        try {
            self::service()->syncPolicies($user, [self::role('editor')]); // @phpstan-ignore argument.type
            self::fail('The role was not refused.');
        } catch (InvalidGrantTargetException $exception) {
            self::assertSame('policy', $exception->getKind());
        }

        $this->expectExceptionObject(new InvalidGrantTargetException('policy', 'audit'));

        self::service()->syncPolicies($user, ['audit']); // @phpstan-ignore argument.type
    }

    /**
     * Permissions are granted, revoked and synced with their own events.
     *
     * @return void
     */
    public function testPermissionsAreGrantedRevokedAndSynced(): void
    {
        $user   = self::user();
        $edit   = Permission::query()->create(['name' => 'posts:edit']);
        $delete = Permission::query()->create(['name' => 'posts:delete']);

        Event::fake();

        self::assertSame(GrantOutcome::GRANTED, self::service()->grantPermission($user, 'posts:edit', Carbon::parse('2026-07-02 12:00:00', 'UTC')));
        self::assertSame(GrantOutcome::EXPIRY_CHANGED, self::service()->grantPermission($user, $edit));
        self::assertSame(GrantOutcome::UNCHANGED, self::service()->grantPermission($user, $edit));
        self::assertSame([$delete->id], self::service()->syncPermissions($user, [$edit, $delete])->granted);
        self::assertSame(1, self::service()->revokePermission($user, 'posts:edit'));
        self::assertSame(0, self::service()->revokePermission($user, $edit));
        self::assertSame(['posts:delete'], $user->getPermissions());

        Event::assertDispatchedTimes(PermissionGranted::class, 3);
        Event::assertDispatchedTimes(PermissionExpiryChanged::class, 1);
        Event::assertDispatchedTimes(PermissionRevoked::class, 1);
    }

    /**
     * A permission name is looked up through the configured permission class.
     *
     * @return void
     */
    public function testAPermissionNameIsLookedUpThroughTheConfiguredClass(): void
    {
        $this->config()->set('authorization.models.permission', CustomPermission::class);

        Permission::query()->create(['name' => 'posts:edit']);

        Event::fake();

        self::service()->grantPermission(self::user(), 'posts:edit');

        Event::assertDispatched(PermissionGranted::class, static fn (PermissionGranted $event): bool => $event->permission->type === (new CustomPermission)->getMorphClass());
    }

    /**
     * An unknown permission name throws.
     *
     * @return void
     */
    public function testAnUnknownPermissionNameThrows(): void
    {
        $this->expectExceptionObject(new UnknownPermissionException('ghost'));

        self::service()->revokePermission(self::user(), 'ghost');
    }

    /**
     * Policies are attached, detached and synced with their own events.
     *
     * @return void
     */
    public function testPoliciesAreAttachedDetachedAndSynced(): void
    {
        $user   = self::user();
        $audit  = self::policy('audit');
        $review = self::policy('review');

        Event::fake();

        self::assertSame(GrantOutcome::GRANTED, self::service()->attachPolicy($user, $audit, Carbon::parse('2026-07-02 12:00:00', 'UTC')));
        self::assertSame(GrantOutcome::EXPIRY_CHANGED, self::service()->attachPolicy($user, $audit));
        self::assertSame([$review->id], self::service()->syncPolicies($user, [$audit, $review])->granted);
        self::assertSame(1, self::service()->detachPolicy($user, $audit));
        self::assertSame(0, self::service()->detachPolicy($user, $audit));
        self::assertSame([$review->id], self::service()->syncPolicies($user, [])->revoked);

        Event::assertDispatchedTimes(PolicyAttached::class, 3);
        Event::assertDispatchedTimes(PolicyExpiryChanged::class, 1);
        Event::assertDispatchedTimes(PolicyDetached::class, 2);
    }

    /**
     * A sync result with no change reports none.
     *
     * @return void
     */
    public function testASyncResultReportsWhetherItChanged(): void
    {
        self::assertFalse((new SyncResult)->isChange());
        self::assertTrue((new SyncResult(granted: ['a']))->isChange());
        self::assertTrue((new SyncResult(rearmed: ['a']))->isChange());
        self::assertTrue((new SyncResult(revoked: ['a']))->isChange());
    }

    /**
     * Every event a call dispatches carries the actor the caller passed, and
     * every grant row it writes records that actor; a call that names none
     * records none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRecordsTheActorOnTheEventsAndTheRows(): void
    {
        Event::fake();

        $user  = self::user();
        $actor = StubIdentity::query()->create(['id' => 'admin-1']);

        self::service()->grantRole($user, self::role('editor'), actor: $actor);
        self::service()->grantPermission($user, Permission::query()->create(['name' => 'posts:edit']), actor: new Reference('service', 'importer'));
        self::service()->attachPolicy($user, self::policy('audit'));

        self::assertSame([$actor->getMorphClass(), 'admin-1'], self::grantor('authorizable_roles'));
        self::assertSame(['service', 'importer'], self::grantor('authorizable_permissions'));
        self::assertSame([null, null], self::grantor('authorizable_policies'));
        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => self::refersTo($event->operation->actor, $actor));
        Event::assertDispatched(
            PermissionGranted::class,
            static fn (PermissionGranted $event): bool => self::refersTo($event->operation->actor, new Reference('service', 'importer')),
        );
        Event::assertDispatched(PolicyAttached::class, static fn (PolicyAttached $event): bool => $event->operation->actor === null);
    }

    /**
     * A revocation and a sync carry the actor too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevocationsAndSyncsCarryTheActor(): void
    {
        $user  = self::user();
        $actor = new Reference('user', 'admin-1');

        self::service()->grantRole($user, self::role('editor'));
        self::role('author');

        Event::fake();

        self::service()->revokeRole($user, 'editor', $actor);
        self::service()->syncRoles($user, ['author'], actor: $actor);

        Event::assertDispatched(RoleRevoked::class, static fn (RoleRevoked $event): bool => self::refersTo($event->operation->actor, $actor));
        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => self::refersTo($event->operation->actor, $actor));
        self::assertSame(['user', 'admin-1'], self::grantor('authorizable_roles'));
    }

    /**
     * Every event one call dispatches shares the call's operation id, and
     * another call has an id of its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryEventOfOneCallSharesItsOperationId(): void
    {
        $user = self::user();

        self::service()->grantRole($user, self::role('editor'), Carbon::parse('2026-07-02 12:00:00', 'UTC'));
        self::service()->grantRole($user, self::role('viewer'));
        self::role('author');

        Event::fake();

        self::service()->syncRoles($user, ['editor', 'author'], Carbon::parse('2026-07-03 12:00:00', 'UTC'));

        $ids = [
            ...\array_map(static fn (RoleAssigned $event): string => $event->operation->id, self::dispatchedEvents(RoleAssigned::class)),
            ...\array_map(static fn (RoleRevoked $event): string => $event->operation->id, self::dispatchedEvents(RoleRevoked::class)),
        ];

        self::assertCount(2, $ids);
        self::assertCount(1, \array_unique($ids));

        self::service()->grantRole($user, 'viewer');

        $later = \array_values(\array_diff(\array_map(static fn (RoleAssigned $event): string => $event->operation->id, self::dispatchedEvents(RoleAssigned::class)), $ids));

        self::assertCount(1, $later);
        self::assertCount(2, self::dispatchedEvents(RoleAssigned::class));
    }

    /**
     * A grant made inside an enclosing transaction is reported once that
     * transaction commits, not before, and once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantIsReportedOnceTheEnclosingTransactionCommits(): void
    {
        Event::fake();

        $user = self::user();
        $role = self::role('editor');

        DB::transaction(static function () use ($user, $role): void {
            DB::transaction(static fn () => self::service()->grantRole($user, $role));

            Event::assertNotDispatched(RoleAssigned::class);
        });

        Event::assertDispatchedTimes(RoleAssigned::class, 1);
    }

    /**
     * A grant whose enclosing transaction rolls back is never reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantRolledBackWithItsEnclosingTransactionIsNeverReported(): void
    {
        Event::fake();

        $user = self::user();
        $role = self::role('editor');

        try {
            DB::transaction(static function () use ($user, $role): never {
                self::service()->grantRole($user, $role);
                self::service()->revokeRole($user, $role);
                self::service()->attachPolicy($user, self::policy('audit'));

                throw new \RuntimeException('Rolled back.');
            });
        } catch (\RuntimeException) {
            // The enclosing transaction rolled back.
        }

        self::assertSame(0, DB::table('authorizable_policies')->count());
        Event::assertNotDispatched(RoleAssigned::class);
        Event::assertNotDispatched(RoleRevoked::class);
        Event::assertNotDispatched(PolicyAttached::class);
    }

    /**
     * The events name the grantee, the target and the actor by their morph
     * types under the application's morph map, and the grant as platform-wide
     * with its expiry in UTC.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheEventsUseTheMorphMap(): void
    {
        Relation::morphMap(['member' => StubIdentity::class, 'role' => Role::class]);

        try {
            Event::fake();

            $user = self::user();
            $role = self::role('editor');

            self::service()->grantRole($user, $role, Carbon::parse('2026-07-02 14:00:00', 'Europe/Paris'), StubIdentity::query()->create(['id' => 'admin-1']));

            Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => $event->grantee->type === 'member'
                && $event->grantee->id                                                                                  === 'user-1'
                && $event->role->type                                                                                   === 'role'
                && $event->role->id                                                                                     === $role->id
                && $event->name                                                                                         === 'editor'
                && $event->operation->actor?->type                                                                      === 'member'
                && $event->scope->tenant                                                                                === null
                && $event->scope->application                                                                           === null
                && $event->expiresAt?->format('Y-m-d H:i:s e')                                                          === '2026-07-02 12:00:00 UTC');
            self::assertSame(['member', 'admin-1'], self::grantor('authorizable_roles'));
        } finally {
            Relation::morphMap([], false);
        }
    }

    /**
     * An inline policy is attached to the grantee it belongs to, and attaching
     * or syncing it to any other grantee, an identity or a role, is refused
     * before anything is written or reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInlinePolicyIsAttachedOnlyToItsGrantee(): void
    {
        $user    = self::user();
        $other   = new Reference($user->getMorphClass(), 'user-2');
        $role    = self::role('editor');
        $inline  = Policy::query()->create(['name' => 'mine', 'document' => ['statements' => []], 'owner_type' => $user->getMorphClass(), 'owner_id' => 'user-1']);
        $managed = self::policy('shared');

        self::assertSame(GrantOutcome::GRANTED, self::service()->attachPolicy(Reference::of($user), $inline));

        self::service()->attachPolicy($other, $managed);

        Event::fake([PolicyAttached::class, PolicyDetached::class]);

        $refusals = [
            'attach to another identity' => static fn () => self::service()->attachPolicy($other, $inline),
            'attach to a role'           => static fn () => self::service()->attachPolicy($role, $inline),
            'sync to another identity'   => static fn () => self::service()->syncPolicies($other, [$inline]),
        ];

        foreach ($refusals as $write => $refused) {
            try {
                $refused();
                self::fail("The grant service allowed the write: {$write}.");
            } catch (InlinePolicyAttachmentException $exception) {
                self::assertSame('mine', $exception->getPolicyName(), $write);
                self::assertTrue(self::refersTo($exception->getOwner(), $user), $write);
            }
        }

        Event::assertNotDispatched(PolicyAttached::class);
        Event::assertNotDispatched(PolicyDetached::class);
        self::assertEqualsCanonicalizing(['user-1', 'user-2'], DB::table('authorizable_policies')->pluck('authorizable_id')->all());
    }

    /**
     * A policy attached to and detached from a role is reported with the role
     * as the grantee, in the scope it was attached in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyAttachedToARoleIsReportedWithTheRoleAsGrantee(): void
    {
        $role   = self::role('editor');
        $policy = self::policy('editors');

        Event::fake([PolicyAttached::class, PolicyDetached::class]);

        self::assertSame(GrantOutcome::GRANTED, self::service()->attachPolicy($role, $policy, application: 'admin'));
        self::assertSame(1, self::service()->detachPolicy($role, $policy, application: 'admin'));

        Event::assertDispatched(PolicyAttached::class, static fn (PolicyAttached $event): bool => self::refersTo($event->grantee, $role) && $event->scope->application === 'admin');
        Event::assertDispatched(
            PolicyDetached::class,
            static fn (PolicyDetached $event): bool => self::refersTo($event->grantee, $role) && self::refersTo($event->policy, $policy),
        );
    }

    /**
     * Assert that no grant event was dispatched.
     *
     * @return void
     */
    private static function assertNoGrantEvents(): void
    {
        $events = [
            RoleAssigned::class, RoleRevoked::class, RoleExpiryChanged::class,
            PermissionGranted::class, PermissionRevoked::class, PermissionExpiryChanged::class,
            PolicyAttached::class, PolicyDetached::class, PolicyExpiryChanged::class,
        ];

        foreach ($events as $event) {
            Event::assertNotDispatched($event);
        }
    }

    /**
     * Return the names of the roles the identity holds live, read afresh.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return list<string>
     */
    private static function heldRoleNames(StubIdentity $user): array
    {
        /** @var list<string> */
        return $user->roles()->pluck('name')->all();
    }

    /**
     * Return the grantor columns of the one row in a grant table.
     *
     * @param  string  $table
     * @return array{mixed, mixed}
     */
    private static function grantor(string $table): array
    {
        $row = DB::table($table)->sole(['granted_by_type', 'granted_by_id']);

        return [$row->granted_by_type, $row->granted_by_id];
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function service(): GrantService
    {
        return app(GrantService::class);
    }

    /**
     * Create the stub identity.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function user(): StubIdentity
    {
        return StubIdentity::query()->create(['id' => 'user-1']);
    }

    /**
     * Create a platform-wide role.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function role(string $name): Role
    {
        return Role::query()->create(['name' => $name]);
    }

    /**
     * Create a policy.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name): Policy
    {
        return Policy::query()->create(['name' => $name, 'document' => ['statements' => []]]);
    }

    /**
     * Return each role grant's expiry by role, sorted by role.
     *
     * @return array<string, string|null>
     */
    private static function expiries(): array
    {
        /** @var array<string, string|null> */
        return DB::table('authorizable_roles')->pluck('expires_at', 'role_id')->sortKeys()->all();
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        /** @var \Illuminate\Config\Repository */
        return $this->app?->make(ConfigRepository::class);
    }
}
