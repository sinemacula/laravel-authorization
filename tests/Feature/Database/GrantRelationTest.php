<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\JoinClause;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Database\GrantRelation;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\NumberedGrantee;
use Tests\Feature\Stubs\StubGrantee;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for the grantee's relation onto its grants, which binds the
 * grantee's key as a string, alone and eager-loaded, and reads the rows given
 * in place of the grant table, while writing to the table itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantRelation::class)]
final class GrantRelationTest extends TestCase
{
    use ActivatesBreakGlass, ActsAsTenant;

    /** @var list<string> The permission grant table and its keys, as a grantee's permissions relation names them. */
    private const array PERMISSION_GRANTS = ['authorizable_permissions', 'authorizable_id', 'permission_id', 'id', 'id'];

    /**
     * One grantee's grants are read by its key as a string and its morph type.
     *
     * @return void
     */
    public function testAGranteesKeyIsBoundAsAString(): void
    {
        $user = NumberedGrantee::create(['name' => 'Ada']);

        $user->assignRole(Role::create(['name' => 'editor']));
        StubGrantee::create(['id' => (string) $user->id])->assignRole(Role::create(['name' => 'other']));

        $relation = $user->roles();

        self::assertInstanceOf(GrantRelation::class, $relation);
        self::assertSame([(string) $user->id, $user->getMorphClass()], \array_slice($relation->getQuery()->getQuery()->getRawBindings()['where'], 0, 2));
        self::assertSame(['editor'], $relation->pluck('name')->all());
    }

    /**
     * An eager load binds every grantee's key as a string, matches each grant
     * to its grantee, and leaves another type's grants with the same key out.
     *
     * @return void
     */
    public function testAnEagerLoadBindsEveryKeyAsAString(): void
    {
        $first  = NumberedGrantee::create(['name' => 'Ada']);
        $second = NumberedGrantee::create(['name' => 'Grace']);

        $first->assignRole(Role::create(['name' => 'editor']));
        StubGrantee::create(['id' => (string) $second->id])->assignRole(Role::create(['name' => 'other']));

        DB::flushQueryLog();
        DB::enableQueryLog();

        $loaded = NumberedGrantee::query()->with('roles')->orderBy('id')->get();

        $bindings = \array_merge(...\array_column(DB::getQueryLog(), 'bindings'));

        DB::disableQueryLog();

        self::assertContains((string) $first->id, $bindings);
        self::assertContains((string) $second->id, $bindings);
        self::assertNotContains($first->id, $bindings);
        self::assertSame([['editor'], []], $loaded->map(static fn (NumberedGrantee $user): array => $user->roles->pluck('name')->all())->all());
    }

    /**
     * Given rows to read in place of the grant table, the relation reads them
     * under the table's name, alone, eager-loaded and as an existence check,
     * while a write through it goes to the table; without, it reads the table.
     *
     * @return void
     */
    public function testRowsGivenAreReadInPlaceOfTheTable(): void
    {
        $user       = StubGrantee::create(['id' => 'user-1']);
        $permission = Permission::create(['name' => 'posts:read']);
        $other      = Permission::create(['name' => 'posts:edit']);
        $columns    = ['permission_id', 'authorizable_type', 'authorizable_id', 'tenant_type', 'tenant_id', 'application', 'expires_at', 'created_at', 'updated_at'];
        $rows       = DB::table('authorizable_permissions')->select($columns)
            ->unionAll(DB::query()->selectRaw('?, ?, ?, null, null, null, null, ?, ?', [$other->id, $user->getMorphClass(), 'user-1', Carbon::now(), Carbon::now()]));
        $relation = static fn (): GrantRelation => (new GrantRelation($permission->newQuery(), $user, 'authorizable', ...self::PERMISSION_GRANTS))
            ->readingRows($rows)
            ->withTimestamps();

        $relation()->attach($permission->id);

        self::assertSame(1, DB::table('authorizable_permissions')->count());
        self::assertSame(['posts:read', 'posts:edit'], $relation()->orderBy('name', 'desc')->pluck('name')->all());
        self::assertSame(['posts:read'], $user->permissions()->pluck('name')->all());
        self::assertStringContainsString('join (', $relation()->getRelationExistenceQuery(Permission::query(), StubGrantee::query())->toSql());
        self::assertStringContainsString('join (', $relation()->toSql());
        self::assertStringNotContainsString('join (', $user->permissions()->toSql());
        self::assertCount(1, $relation()->getQuery()->getQuery()->joins ?? []);

        $plain = new GrantRelation($permission->newQuery(), $user, 'authorizable', ...self::PERMISSION_GRANTS);

        self::assertSame($plain, $plain->readingRows(null));
        self::assertSame(['authorizable_permissions'], \array_map(static fn (JoinClause $join): mixed => $join->table, $plain->getQuery()->getQuery()->joins ?? []));
    }

    /**
     * Provide each grantee relation onto one kind of grant.
     *
     * @return iterable<string, array{string}>
     */
    public static function grantKinds(): iterable
    {
        foreach (['roles', 'permissions', 'policies'] as $relation) {
            yield $relation => [$relation];
        }
    }

    /**
     * An existence query or count over a grantee's grants of one kind reads
     * only the live grants in the current tenant and application of its own
     * type, comparing an integer key with the stored string key.
     *
     * @param  string  $relation
     * @return void
     */
    #[DataProvider('grantKinds')]
    public function testExistenceQueriesReadOnlyLiveGrantsInScope(string $relation): void
    {
        $tenantA    = self::createTenant('tenant-a');
        $tenantB    = self::createTenant('tenant-b');
        $role       = Role::create(['name' => 'granted']);
        $permission = Permission::create(['name' => 'granted']);
        $policy     = Policy::create(['name' => 'granted', 'document' => ['statements' => []]]);
        $grant      = static fn (NumberedGrantee|StubGrantee $user, ?StubTenant $tenant, ?\DateTimeInterface $until = null, ?string $app = null): mixed => match ($relation) {
            'roles'       => $user->assignRole($role, $until, $tenant, application: $app),
            'permissions' => $user->givePermission($permission, $until, $tenant, application: $app),
            default       => $user->attachPolicy($policy, $until, $tenant, application: $app),
        };
        $users = [];

        foreach (['live', 'expired', 'elsewhere', 'platform', 'mobile', 'expiring'] as $name) {
            $users[$name] = NumberedGrantee::create(['name' => $name]);
        }

        $grant($users['live'], $tenantA);
        $grant($users['expired'], $tenantA, Carbon::now()->addHour());
        $grant($users['elsewhere'], $tenantB);
        $grant($users['platform'], null);
        $grant($users['mobile'], $tenantA, app: 'mobile');
        $grant($users['expiring'], $tenantA, Carbon::now()->addHours(3));
        $grant(StubGrantee::create(['id' => (string) $users['elsewhere']->id]), $tenantA);

        $this->travel(2)->hours();
        $this->actAsTenant($tenantA);

        $named   = static fn (Builder $query): Builder => $query->where($query->qualifyColumn('name'), 'granted');
        $holders = NumberedGrantee::query()->whereHas($relation, $named)->orderBy('id')->pluck('name')->all();
        $counts  = NumberedGrantee::query()->withCount($relation)->orderBy('id')->pluck($relation . '_count', 'name')->all();
        $inApp   = TenantScope::within($tenantA, 'mobile', static fn (): array => NumberedGrantee::query()->has($relation)->orderBy('id')->pluck('name')->all());

        self::assertSame(['live', 'platform', 'expiring'], $holders);
        self::assertSame(['live' => 1, 'expired' => 0, 'elsewhere' => 0, 'platform' => 1, 'mobile' => 0, 'expiring' => 1], $counts);
        self::assertSame(['live', 'platform', 'mobile', 'expiring'], $inApp);
    }

    /**
     * Eager-loading the roles of several grantees in a tenant gives each only
     * its own live grants there and its own live activations there.
     *
     * @return void
     */
    public function testAnEagerLoadInATenantReadsEachGranteesLiveRolesThere(): void
    {
        $tenantA = self::createTenant('tenant-a');
        $tenantB = self::createTenant('tenant-b');
        $inA     = ['tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => 'tenant-a'];
        $first   = NumberedGrantee::create(['name' => 'first']);
        $second  = NumberedGrantee::create(['name' => 'second']);
        $third   = NumberedGrantee::create(['name' => 'third']);

        $first->assignRole(Role::create(['name' => 'editor']), tenant: $tenantA);
        $first->assignRole(Role::create(['name' => 'expired']), Carbon::now()->addHour(), $tenantA);
        $first->assignRole(Role::create(['name' => 'b-only']), tenant: $tenantB);
        $second->assignRole(Role::create(['name' => 'viewer']));
        $third->assignRole(Role::query()->where('name', 'b-only')->firstOrFail(), tenant: $tenantB);

        $this->travel(2)->hours();

        self::activate($second, self::emergencyRole(), $inA);
        self::activate($second, self::emergencyRole(name: 'ended'), [...$inA, 'ended_at' => Carbon::now(), 'end_reason' => 'revoked']);
        self::activate($second, self::emergencyRole(name: 'lapsed'), [...$inA, 'activated_at' => Carbon::now()->subHour(), 'expires_at' => Carbon::now()->subMinute()]);
        self::activate($third, self::emergencyRole(name: 'b-responder'), ['tenant_type' => $tenantB->getMorphClass(), 'tenant_id' => 'tenant-b']);

        $this->actAsTenant($tenantA);

        $loaded = NumberedGrantee::query()->with('roles')->orderBy('id')->get();
        $roles  = $loaded->mapWithKeys(static fn (NumberedGrantee $user): array => [$user->name => $user->roles->pluck('name')->sort()->values()->all()])->all();

        self::assertSame(['first' => ['editor'], 'second' => ['responder', 'viewer'], 'third' => []], $roles);
    }
}
