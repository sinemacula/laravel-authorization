<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Events\Grantee\RoleAssigned;
use SineMacula\Laravel\Authorization\Exceptions\GrantScopeMismatchException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\AssertsDelegatedRefusals;
use Tests\Feature\Stubs\StubGrantee;
use Tests\TestCase;

/**
 * Feature tests for the grant service at the edges of its scopes: where a name
 * is looked up and a grant written with a tenant current, a revocation naming
 * the wrong tenant, the grantor a delegated sync records, and the relations
 * revoking everything clears.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantService::class)]
final class GrantServiceEdgeCasesTest extends TestCase
{
    use ActsAsAdministrator, ActsAsTenant, AssertsDelegatedRefusals;

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
     * With no tenant named, a name is looked up only among the rows visible in
     * the current tenant, so outside the tenant a role it owns is unknown, or
     * answered by the platform's role of the name, until the tenant is named.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationByNameWithNoTenantNamedLooksInTheCurrentTenant(): void
    {
        $user   = self::user();
        $tenant = self::createTenant('tenant-a');
        $owned  = self::role('editor', self::ownedBy($tenant));

        self::service()->grantRole($user, $owned);

        try {
            self::service()->revokeRole($user, 'editor');
            self::fail('A role only another tenant owns was found.');
        } catch (UnknownRoleException) {
            self::role('editor');
        }

        self::assertSame(0, self::service()->revokeRole($user, 'editor'));
        self::assertSame([$owned->id], DB::table('authorizable_roles')->pluck('role_id')->all());
        self::assertSame(1, self::service()->revokeRole($user, 'editor', null, $tenant));
    }

    /**
     * A platform role granted while a tenant is current and none is named is
     * granted platform-wide, never in the current tenant alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformRoleIsGrantedPlatformWideWhateverTheCurrentTenant(): void
    {
        $user = self::user();

        self::role('editor');
        $this->actAsTenant(self::createTenant('tenant-a'));

        Event::fake([RoleAssigned::class]);

        self::service()->grantRole($user, 'editor');

        $row = DB::table('authorizable_roles')->sole(['tenant_type', 'tenant_id']);

        self::assertSame([null, null], [$row->tenant_type, $row->tenant_id]);
        Event::assertDispatched(RoleAssigned::class, static fn (RoleAssigned $event): bool => $event->scope->tenant === null);
    }

    /**
     * Revoking a role, permission or policy one tenant owns while naming
     * another tenant is refused, as granting it there is, and revokes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingAnOwnedTargetInAnotherTenantIsRefused(): void
    {
        $user   = self::user();
        $tenant = self::createTenant('tenant-a');
        $other  = self::createTenant('tenant-b');
        $role   = self::role('editor', self::ownedBy($tenant));
        $edit   = Permission::query()->create(['name' => 'posts:edit', ...self::ownedBy($tenant)]);
        $policy = Policy::query()->create(['name' => 'audit', 'document' => ['statements' => []], ...self::ownedBy($tenant)]);

        self::service()->grantRole($user, $role);
        self::service()->grantPermission($user, $edit);
        self::service()->attachPolicy($user, $policy);
        self::fakePackageEvents();

        $revocations = [
            'role'       => static fn (): int => self::service()->revokeRole($user, $role, null, $other),
            'permission' => static fn (): int => self::service()->revokePermission($user, $edit, null, $other),
            'policy'     => static fn (): int => self::service()->detachPolicy($user, $policy, null, $other),
        ];

        foreach ($revocations as $kind => $revoke) {
            try {
                $revoke();
                self::fail("A {$kind} revoked in another tenant was not refused.");
            } catch (GrantScopeMismatchException $exception) {
                self::assertSame([$kind, 'tenant-b'], [$exception->getKind(), $exception->getScope()?->id]);
            }
        }

        $tables = ['authorizable_roles', 'authorizable_permissions', 'authorizable_policies'];

        self::assertSame([1, 1, 1], \array_map(static fn (string $table): int => DB::table($table)->count(), $tables));
        self::assertSame([], self::changesDispatched());
    }

    /**
     * A delegated sync records the actor on every row it grants or re-arms, and
     * leaves the grantor of a row it keeps live as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADelegatedSyncRecordsTheActorOnEveryRowItWrites(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $admin  = self::administrator();
        $user   = self::user();
        $kept   = self::role('kept');
        $lapsed = self::role('lapsed');
        $added  = self::role('added');

        self::service()->grantRole($user, $kept);
        self::service()->grantRole($user, $lapsed, Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        Carbon::setTestNow('2026-07-01 14:00:00');

        $result = self::service()->syncRoles($user, [$kept, $lapsed, $added], actor: $admin);
        $actor  = [$user->getMorphClass(), 'admin-1'];
        $rows   = DB::table('authorizable_roles')->where('authorizable_id', 'user-1')->get(['role_id', 'granted_by_type', 'granted_by_id']);

        self::assertSame([[$added->id], [$lapsed->id]], [$result->granted, $result->rearmed]);
        self::assertEqualsCanonicalizing(
            [[$kept->id, null, null], [$lapsed->id, ...$actor], [$added->id, ...$actor]],
            $rows->map(static fn (object $row): array => \array_values((array) $row))->all(),
        );
    }

    /**
     * Revoking everything clears the grantee's loaded roles, permissions and
     * policies, so the next read sees none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingEverythingClearsTheLoadedRelations(): void
    {
        $user = self::user();

        self::service()->grantRole($user, self::role('editor'));
        self::service()->grantPermission($user, Permission::query()->create(['name' => 'posts:edit']));
        self::service()->attachPolicy($user, Policy::query()->create(['name' => 'audit', 'document' => ['statements' => []]]));

        $user->load(['roles', 'permissions', 'policies']);

        self::service()->revokeAll($user);

        self::assertSame([0, 0, 0], [$user->roles->count(), $user->permissions->count(), $user->policies->count()]);
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
     * Create the stub grantee.
     *
     * @return \Tests\Feature\Stubs\StubGrantee
     */
    private static function user(): StubGrantee
    {
        return StubGrantee::query()->create(['id' => 'user-1']);
    }

    /**
     * Create a role, platform-wide unless the attributes name an owner.
     *
     * @param  string  $name
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function role(string $name, array $attributes = []): Role
    {
        return Role::query()->create(['name' => $name, ...$attributes]);
    }
}
