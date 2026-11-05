<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
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
use SineMacula\Laravel\Authorization\Exceptions\InvalidGranteeException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\SyncResult;
use SineMacula\Laravel\Authorization\Support\GranteeReference;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\AssertsTransactions;
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
    use ActsAsTenant, AssertsTransactions, UsesAnAuthorizationConnection;

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
        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => $event->authorizable === $user && $event->role === $role);
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
        Event::assertDispatched(RoleExpiryChanged::class, static fn (RoleExpiryChanged $event): bool => $event->authorizable === $user
            && $event->role                                                                                                  === $role
            && $event->previousExpiresAt?->getTimestamp()                                                                    === $before->getTimestamp()
            && $event->newExpiresAt                                                                                          === $after);
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

        self::service()->grantRole($grantee, 'editor');

        self::assertSame([$web->id], DB::table('authorizable_roles')->where('authorizable_id', 'hooked')->pluck('role_id')->all());
    }

    /**
     * Grantees a grant cannot be written for: an unsaved model, a saved model
     * with an empty key, and a reference with an empty type or key.
     *
     * @return iterable<string, array{\Closure(): (\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference), string}>
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
        yield 'a reference with an empty key' => [static fn (): GranteeReference => new GranteeReference('App\Models\User', ''), 'an incomplete ' . GranteeReference::class];
        yield 'a reference with an empty type' => [static fn (): GranteeReference => new GranteeReference('', '42'), 'an incomplete ' . GranteeReference::class];
    }

    /**
     * A grant, revocation or sync for a grantee a grant cannot be written for
     * is refused before anything is read or written, and dispatches nothing.
     *
     * @param  \Closure(): (\Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\GranteeReference)  $grantee
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

        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => $event->role instanceof CustomRole);
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
    public function testGrantsToAGranteeReference(): void
    {
        Event::fake();

        $grantee = new GranteeReference('App\Models\User', '42');
        $role    = self::role('editor');

        self::service()->grantRole($grantee, $role);

        $row = DB::table('authorizable_roles')->sole();

        self::assertSame('App\Models\User', $row->authorizable_type);
        self::assertSame('42', $row->authorizable_id);
        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => $event->authorizable === $grantee);
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
        Event::assertDispatched(RoleRevoked::class, static fn (RoleRevoked $event): bool => $event->authorizable === $user && $event->role === $role);
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
     * Revoking a role removes its rows in every scope, since every row counts
     * platform-wide until scope is read.
     *
     * @return void
     */
    public function testRevokingRemovesTheRoleInEveryScope(): void
    {
        $user = self::user();
        $role = self::role('editor');

        DB::table('authorizable_roles')->insert([
            'role_id'           => $role->id,
            'authorizable_type' => $user->getMorphClass(),
            'authorizable_id'   => 'user-1',
            'tenant_type'       => 'stub_tenant',
            'tenant_id'         => 'tenant-a',
        ]);

        self::assertSame(1, self::service()->revokeRole($user, $role));
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
        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => $event->role->is($joined));
        Event::assertDispatched(RoleRevoked::class, static fn (RoleRevoked $event): bool => $event->authorizable === $user && $event->role->is($gone));
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
     * A name in a sync keeps every held role of that name, and only when none
     * is held is the first the lookup ranks granted.
     *
     * @return void
     */
    public function testASyncNameKeepsTheHeldRolesOfIt(): void
    {
        $user   = self::user();
        $tenant = self::createTenant('tenant-a');
        $global = self::role('editor');
        $scoped = Role::query()->create(['name' => 'editor', ...self::ownedBy($tenant)]);

        $this->actAsTenant($tenant);

        self::service()->grantRole($user, $global);

        $result = self::service()->syncRoles($user, ['editor']);

        self::assertFalse($result->isChange());
        self::assertSame([$global->id], DB::table('authorizable_roles')->pluck('role_id')->all());

        self::service()->syncRoles($user, []);

        self::assertSame([$scoped->id], self::service()->syncRoles($user, ['editor'])->granted);
    }

    /**
     * A sync reports a revoked role of another tenant, outside the tenant
     * scope.
     *
     * @return void
     */
    public function testASyncReportsARevokedRoleOfAnotherTenant(): void
    {
        $user  = self::user();
        $other = Role::query()->create(['name' => 'editor', ...self::ownedBy(self::createTenant('tenant-a'))]);

        self::service()->grantRole($user, $other);

        $this->actAsTenant(self::createTenant('tenant-b'));

        Event::fake();

        self::assertSame([$other->id], self::service()->syncRoles($user, [])->revoked);
        Event::assertDispatched(RoleRevoked::class, static fn (RoleRevoked $event): bool => $event->role->is($other));
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

        Event::assertDispatched(PermissionGranted::class, static fn (PermissionGranted $event): bool => $event->permission instanceof CustomPermission);
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
