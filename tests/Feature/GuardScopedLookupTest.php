<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use Tests\Concerns\ActsAsTenant;
use Tests\TestCase;

/**
 * Feature tests for the precedence `GuardScopedLookup::findForGuard()` and
 * `allForGuard()` apply when several rows answer a name: the current tenant's
 * row over the platform's, then a row for the guard over a guard-agnostic one,
 * then the primary key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GuardScopedLookup::class)]
final class GuardScopedLookupTest extends TestCase
{
    use ActsAsTenant;

    /**
     * Each of the four rows that can answer a role name is found in turn, as
     * the ones that outrank it are removed: the tenant's row for the guard, the
     * tenant's guard-agnostic row, the platform's row for the guard and the
     * platform's guard-agnostic row.
     *
     * @return void
     */
    public function testRolePrecedenceIsTenantThenGuard(): void
    {
        $this->assertPrecedence(Role::class);
    }

    /**
     * Permissions follow the same precedence as roles.
     *
     * @return void
     */
    public function testPermissionPrecedenceIsTenantThenGuard(): void
    {
        $this->assertPrecedence(Permission::class);
    }

    /**
     * Another tenant's row is never found, even when it is the only row for the
     * guard.
     *
     * @return void
     */
    public function testAnotherTenantsRowIsNeverFound(): void
    {
        $tenantA = self::createTenant('tenant-a');
        $tenantB = self::createTenant('tenant-b');

        $platform = Role::query()->create(['name' => 'editor', 'guard' => null]);
        Role::query()->create(['name' => 'editor', 'guard' => 'web'] + self::ownedBy($tenantB));

        $this->actAsTenant($tenantA);

        self::assertSame($platform->id, GuardScopedLookup::findForGuard(Role::class, 'editor', 'web')?->getKey());
    }

    /**
     * Without a tenant only the platform's rows answer.
     *
     * @return void
     */
    public function testWithoutATenantOnlyThePlatformRowIsFound(): void
    {
        $tenant   = self::createTenant('tenant-a');
        $platform = Role::query()->create(['name' => 'editor', 'guard' => 'web']);

        Role::query()->create(['name' => 'editor', 'guard' => 'web'] + self::ownedBy($tenant));

        $this->actAsTenant(null);

        self::assertSame($platform->id, GuardScopedLookup::findForGuard(Role::class, 'editor', 'web')?->getKey());
    }

    /**
     * A row for another guard never answers.
     *
     * @return void
     */
    public function testARowForAnotherGuardIsNeverFound(): void
    {
        Role::query()->create(['name' => 'editor', 'guard' => 'api']);

        self::assertNull(GuardScopedLookup::findForGuard(Role::class, 'editor', 'web'));
    }

    /**
     * When rows tie on owner and guard, as they can on a table without the
     * tenant scope, the lowest primary key wins whatever order the rows were
     * written in.
     *
     * @return void
     */
    public function testPrimaryKeyBreaksATie(): void
    {
        Schema::create('lookup_rows', static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('name');
            $table->string('guard')->nullable();
            $table->string('tenant_type')->nullable();
        });

        $row = new class extends Model {
            /** @var bool Ids are written by the test. */
            public $incrementing = false;

            /** @var bool The table has no timestamps. */
            public $timestamps = false;

            /** @var string The key is a string. */
            protected $keyType = 'string';

            /** @var string|null The table the rows live in. */
            protected $table = 'lookup_rows';

            /** @var list<string> Attributes that are mass assignable. */
            protected $fillable = ['id', 'name', 'guard', 'tenant_type'];
        };

        foreach (['row-c', 'row-a', 'row-b'] as $id) {
            $row->newQuery()->create(['id' => $id, 'name' => 'editor', 'guard' => 'web', 'tenant_type' => 'tenant']);
        }

        $found = GuardScopedLookup::findForGuard($row::class, 'editor', 'web')?->getKey();

        Schema::drop('lookup_rows');

        self::assertSame('row-a', $found);
    }

    /**
     * Assert the four-row precedence for the given model class.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Models\Permission|\SineMacula\Laravel\Authorization\Models\Role>  $class
     * @return void
     */
    private function assertPrecedence(string $class): void
    {
        $tenant = self::createTenant('tenant-a');

        // Written from the lowest precedence to the highest, so neither the
        // order of the rows nor their keys can be what picks the winner.
        $rows = [
            $class::query()->create(['name' => 'editor', 'guard' => null]),
            $class::query()->create(['name' => 'editor', 'guard' => 'web']),
            $class::query()->create(['name' => 'editor', 'guard' => null] + self::ownedBy($tenant)),
            $class::query()->create(['name' => 'editor', 'guard' => 'web'] + self::ownedBy($tenant)),
        ];

        $this->actAsTenant($tenant);

        $ranked = \array_map(static fn (Model $row): mixed => $row->getKey(), GuardScopedLookup::allForGuard($class, 'editor', 'web'));

        self::assertSame(\array_map(static fn (Model $row): mixed => $row->getKey(), \array_reverse($rows)), $ranked);

        foreach (\array_reverse($rows) as $expected) {
            self::assertSame($expected->getKey(), GuardScopedLookup::findForGuard($class, 'editor', 'web')?->getKey());

            $expected->delete();
        }

        self::assertNull(GuardScopedLookup::findForGuard($class, 'editor', 'web'));
    }
}
