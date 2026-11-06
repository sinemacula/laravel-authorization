<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\RoleService;
use Tests\Concerns\ActsAsTenant;
use Tests\TestCase;

/**
 * Feature tests for the unique keys of the roles, permissions and policies
 * tables: a name is unique within its owner (the platform, or one tenant) and,
 * for roles and permissions, its guard, not globally; an inline policy's name
 * is unique among its grantee's inline policies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversNothing]
final class OwnerUniquenessTest extends TestCase
{
    use ActsAsTenant;

    /**
     * The guarded models, for the checks that hold for roles and permissions
     * alike.
     *
     * @return iterable<string, array{class-string<\SineMacula\Laravel\Authorization\Models\Permission|\SineMacula\Laravel\Authorization\Models\Role>}>
     */
    public static function guardedModels(): iterable
    {
        yield 'role' => [Role::class];
        yield 'permission' => [Permission::class];
    }

    /**
     * Two tenants may each own a row of the same name and guard.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Models\Permission|\SineMacula\Laravel\Authorization\Models\Role>  $class
     * @return void
     */
    #[DataProvider('guardedModels')]
    public function testTwoTenantsMayShareANameAndGuard(string $class): void
    {
        $class::query()->create(['name' => 'manager', 'guard' => 'web'] + self::ownedBy(self::createTenant('tenant-a')));
        $class::query()->create(['name' => 'manager', 'guard' => 'web'] + self::ownedBy(self::createTenant('tenant-b')));

        self::assertSame(2, self::rows($class));
    }

    /**
     * Two tenants of different types that share an id are different owners, so
     * each may own a row of the same name and guard.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Models\Permission|\SineMacula\Laravel\Authorization\Models\Role>  $class
     * @return void
     */
    #[DataProvider('guardedModels')]
    public function testTenantsOfDifferentTypesSharingAnIdMayShareANameAndGuard(string $class): void
    {
        $class::query()->create(['name' => 'manager', 'guard' => 'web', 'tenant_type' => 'org', 'tenant_id' => '1']);
        $class::query()->create(['name' => 'manager', 'guard' => 'web', 'tenant_type' => 'team', 'tenant_id' => '1']);

        self::assertSame(2, self::rows($class));
    }

    /**
     * A platform row and a tenant's row may share a name and guard.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Models\Permission|\SineMacula\Laravel\Authorization\Models\Role>  $class
     * @return void
     */
    #[DataProvider('guardedModels')]
    public function testAPlatformRowAndATenantRowMayShareANameAndGuard(string $class): void
    {
        $class::query()->create(['name' => 'manager', 'guard' => 'web']);
        $class::query()->create(['name' => 'manager', 'guard' => 'web'] + self::ownedBy(self::createTenant('tenant-a')));

        self::assertSame(2, self::rows($class));
    }

    /**
     * One tenant cannot own two rows of the same name and guard.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Models\Permission|\SineMacula\Laravel\Authorization\Models\Role>  $class
     * @return void
     */
    #[DataProvider('guardedModels')]
    public function testOneTenantCannotOwnTheSameNameAndGuardTwice(string $class): void
    {
        $tenant = self::createTenant('tenant-a');

        $class::query()->create(['name' => 'manager', 'guard' => 'web'] + self::ownedBy($tenant));

        $this->assertRefused(static fn (): Model => $class::query()->create(['name' => 'manager', 'guard' => 'web'] + self::ownedBy($tenant)));
    }

    /**
     * The platform cannot own two rows of the same name and guard, the
     * guard-agnostic slot included.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Models\Permission|\SineMacula\Laravel\Authorization\Models\Role>  $class
     * @return void
     */
    #[DataProvider('guardedModels')]
    public function testThePlatformCannotOwnTheSameNameAndGuardTwice(string $class): void
    {
        $class::query()->create(['name' => 'manager', 'guard' => null]);

        $this->assertRefused(static fn (): Model => $class::query()->create(['name' => 'manager', 'guard' => null]));
    }

    /**
     * One tenant may own a guard-specific and a guard-agnostic row of the same
     * name.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Models\Permission|\SineMacula\Laravel\Authorization\Models\Role>  $class
     * @return void
     */
    #[DataProvider('guardedModels')]
    public function testOneTenantMayOwnAGuardedAndAGuardAgnosticRow(string $class): void
    {
        $tenant = self::createTenant('tenant-a');

        $class::query()->create(['name' => 'manager', 'guard' => 'web'] + self::ownedBy($tenant));
        $class::query()->create(['name' => 'manager', 'guard' => null] + self::ownedBy($tenant));

        self::assertSame(2, self::rows($class));
    }

    /**
     * Each tenant resolves its own row of a shared name and guard.
     *
     * @return void
     */
    public function testEachTenantResolvesItsOwnRow(): void
    {
        $tenantA = self::createTenant('tenant-a');
        $tenantB = self::createTenant('tenant-b');

        $roleA = Role::query()->create(['name' => 'manager', 'guard' => 'web'] + self::ownedBy($tenantA));
        $roleB = Role::query()->create(['name' => 'manager', 'guard' => 'web'] + self::ownedBy($tenantB));

        $this->actAsTenant($tenantA);
        self::assertSame($roleA->id, app(RoleService::class)->find('manager', 'web')->id);

        $this->actAsTenant($tenantB);
        self::assertSame($roleB->id, app(RoleService::class)->find('manager', 'web')->id);
    }

    /**
     * Policy names are unique within their owner: two tenants and the platform
     * may each own a policy of one name.
     *
     * @return void
     */
    public function testPolicyNamesAreUniquePerOwner(): void
    {
        Policy::query()->create(['name' => 'readers', 'document' => self::document()]);
        Policy::query()->create(['name' => 'readers', 'document' => self::document()] + self::ownedBy(self::createTenant('tenant-a')));
        Policy::query()->create(['name' => 'readers', 'document' => self::document()] + self::ownedBy(self::createTenant('tenant-b')));

        self::assertSame(3, self::rows(Policy::class));
    }

    /**
     * Two tenants of different types that share an id may each own a policy of
     * one name.
     *
     * @return void
     */
    public function testTenantsOfDifferentTypesSharingAnIdMayShareAPolicyName(): void
    {
        Policy::query()->create(['name' => 'readers', 'document' => self::document(), 'tenant_type' => 'org', 'tenant_id' => '1']);
        Policy::query()->create(['name' => 'readers', 'document' => self::document(), 'tenant_type' => 'team', 'tenant_id' => '1']);

        self::assertSame(2, self::rows(Policy::class));
    }

    /**
     * The platform cannot own two policies of one name.
     *
     * @return void
     */
    public function testThePlatformCannotOwnAPolicyNameTwice(): void
    {
        Policy::query()->create(['name' => 'readers', 'document' => self::document()]);

        $this->assertRefused(static fn (): Model => Policy::query()->create(['name' => 'readers', 'document' => self::document()]));
    }

    /**
     * One tenant cannot own two policies of one name.
     *
     * @return void
     */
    public function testOneTenantCannotOwnAPolicyNameTwice(): void
    {
        $tenant = self::createTenant('tenant-a');

        Policy::query()->create(['name' => 'readers', 'document' => self::document()] + self::ownedBy($tenant));

        $this->assertRefused(static fn (): Model => Policy::query()->create(['name' => 'readers', 'document' => self::document()] + self::ownedBy($tenant)));
    }

    /**
     * A grantee cannot own two inline policies of one name, whichever tenant
     * owns them.
     *
     * @return void
     */
    public function testAGranteeCannotOwnAnInlinePolicyNameTwice(): void
    {
        Policy::query()->create(['name' => 'mine', 'document' => self::document()] + self::inline('user', 'user-1'));

        $this->assertRefused(static fn (): Model => Policy::query()->create(['name' => 'mine', 'document' => self::document()] + self::inline('user', 'user-1')));
        $tenant = self::ownedBy(self::createTenant('tenant-a'));

        $this->assertRefused(static fn (): Model => Policy::query()->create(['name' => 'mine', 'document' => self::document()] + self::inline('user', 'user-1') + $tenant));
    }

    /**
     * Two grantees, including two of different types that share an id, may each
     * own an inline policy of one name, and an inline policy may share a
     * managed policy's name.
     *
     * @return void
     */
    public function testInlinePolicyNamesAreUniquePerGrantee(): void
    {
        Policy::query()->create(['name' => 'mine', 'document' => self::document()]);
        Policy::query()->create(['name' => 'mine', 'document' => self::document()] + self::inline('user', '1'));
        Policy::query()->create(['name' => 'mine', 'document' => self::document()] + self::inline('user', '2'));
        Policy::query()->create(['name' => 'mine', 'document' => self::document()] + self::inline('team', '1'));

        self::assertSame(4, self::rows(Policy::class));
    }

    /**
     * Inline policies never take a managed policy's place in its unique key:
     * the platform still owns one managed policy of a name beside a grantee's
     * inline policy of it.
     *
     * @return void
     */
    public function testAnInlinePolicyLeavesTheManagedKeyAlone(): void
    {
        Policy::query()->create(['name' => 'mine', 'document' => self::document()] + self::inline('user', '1'));
        Policy::query()->create(['name' => 'mine', 'document' => self::document()]);

        $this->assertRefused(static fn (): Model => Policy::query()->create(['name' => 'mine', 'document' => self::document()]));
    }

    /**
     * Assert the write is refused by a unique key. On PostgreSQL a failed
     * statement aborts the test's transaction, so the write runs inside a
     * savepoint the failure rolls back.
     *
     * @param  \Closure(): \Illuminate\Database\Eloquent\Model  $write
     * @return void
     *
     * @throws \Throwable
     */
    private function assertRefused(\Closure $write): void
    {
        try {
            DB::transaction($write);
            self::fail('Expected a unique key to refuse the row.');
        } catch (QueryException $exception) {
            self::assertNotSame('', $exception->getMessage());
        }
    }

    /**
     * Count every row of the given model's table, whichever tenant owns it.
     *
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @return int
     */
    private static function rows(string $class): int
    {
        return DB::table((new $class)->getTable())->count();
    }

    /**
     * Return the owner columns of an inline policy of the given grantee.
     *
     * @param  string  $type
     * @param  string  $id
     * @return array{owner_type: string, owner_id: string}
     */
    private static function inline(string $type, string $id): array
    {
        return ['owner_type' => $type, 'owner_id' => $id];
    }

    /**
     * Return a minimal valid policy document.
     *
     * @return array<string, mixed>
     */
    private static function document(): array
    {
        return ['version' => 1, 'statements' => []];
    }
}
