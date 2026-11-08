<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\AuthorityRows;
use SineMacula\Laravel\Authorization\Administration\DependencyPins;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\DependencyPhase;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\RecordsRowLocks;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `AuthorityRows`, which gather the rows that make up
 * authority and lock them through the pins in one fixed order: grant rows,
 * guardrails in the chains named, resource policies, roles and their chains
 * with what they carry, then permissions and policies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorityRows::class)]
final class AuthorityRowsTest extends TestCase
{
    use RecordsRowLocks;

    /** @var list<string> The grant tables, in the order a grantee's rows are locked. */
    private const array GRANTS = ['authorizable_roles', 'authorizable_permissions', 'authorizable_policies', 'authorizable_boundaries'];

    /**
     * A grantee's grant rows are locked table by table, then the roles they
     * hold with the chain above, the permissions those carry and the policies
     * attached to them, then every permission and policy named, each once and
     * sorted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGranteesAuthorityIsLockedInOrder(): void
    {
        $user     = StubIdentity::query()->create(['id' => 'user']);
        $parent   = Role::query()->create(['name' => 'parent']);
        $child    = Role::query()->create(['name' => 'child', 'parent_id' => $parent->getKey()]);
        $read     = Permission::query()->create(['name' => 'posts:read']);
        $edit     = Permission::query()->create(['name' => 'posts:edit']);
        $policy   = Policy::query()->create(['name' => 'readers', 'document' => ['statements' => []]]);
        $boundary = Policy::query()->create(['name' => 'bound', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['*']]]]]);

        self::grants()->grantRole($user, $child);
        self::grants()->grantPermission($user, $edit);
        self::roles()->grantPermission($parent, $read);
        self::grants()->attachPolicy($parent, $policy);
        BoundaryService::instance()?->set($user, $boundary);

        $locks = $this->recordRowLocks();

        AuthorityRows::in(self::pins(), DependencyPhase::ACTOR)->grantees(Reference::of($user), Reference::of($user))->lock();

        $locked = $locks->getArrayCopy();

        self::assertSame(
            [...self::GRANTS, 'roles', 'role_permissions', 'authorizable_policies', 'permissions', 'policies'],
            \array_column($locked, 0),
        );
        self::assertSame([StubIdentity::class, 'user'], $locked[0][1]);
        self::assertSame(self::sorted([$parent->getKey(), $child->getKey()]), $locked[4][1]);
        self::assertSame(self::sorted([$parent->getKey(), $child->getKey()]), $locked[5][1]);
        self::assertSame([$parent->getMorphClass(), ...self::sorted([$parent->getKey(), $child->getKey()])], $locked[6][1]);
        self::assertSame(self::sorted([$read->getKey(), $edit->getKey()]), $locked[7][1]);
        self::assertSame(self::sorted([$policy->getKey(), $boundary->getKey()]), $locked[8][1]);
    }

    /**
     * The guardrails locked are the platform's and those of every tenant of the
     * chains named, read afresh and pinned, so a moved tenant is noticed; no
     * tenant named locks none, and the platform alone locks the platform's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardrailsOfTheChainsAreLocked(): void
    {
        $child  = new Reference('stub_tenant', 'child');
        $parent = new Reference('stub_tenant', 'parent');
        $tree   = (new StubTenantTree)->put($child, $parent);
        $rail   = Policy::query()->create(['name' => 'rail', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['*']]]]]);

        $this->app?->instance(TenantTree::class, $tree);

        DB::table('guardrails')->insert(['policy_id' => $rail->getKey(), 'tenant_type' => 'stub_tenant', 'tenant_id' => 'parent']);

        $locks = $this->recordRowLocks();
        $pins  = self::pins();

        AuthorityRows::in($pins, DependencyPhase::TARGET)->lock();

        self::assertSame([], $locks->getArrayCopy());

        AuthorityRows::in($pins, DependencyPhase::TARGET)->tenants($child)->lock();

        self::assertSame([['guardrails', ['stub_tenant', 'child', 'stub_tenant', 'parent']], ['policies', [$rail->getKey()]]], $locks->getArrayCopy());

        AuthorityRows::in(self::pins(), DependencyPhase::TARGET)->tenants(null)->lock();

        self::assertSame(['guardrails', []], $locks[2] ?? null);

        $tree->put($child, null);

        $this->expectException(DependencyChangedException::class);

        $pins->validate();
    }

    /**
     * The resource policies of each type named are locked, and the policies
     * attached through them.
     *
     * @return void
     */
    public function testTheResourcePoliciesOfATypeAreLocked(): void
    {
        $policy = Policy::query()->create(['name' => 'shared', 'document' => ['statements' => []]]);

        DB::table('resource_policies')->insert(['policy_id' => $policy->getKey(), 'resource_type' => 'post', 'resource_id' => '1']);

        $locks = $this->recordRowLocks();

        AuthorityRows::in(self::pins(), DependencyPhase::TARGET)->resources('post')->resources('comment')->lock();

        self::assertSame([['resource_policies', ['comment', 'post']], ['policies', [$policy->getKey()]]], $locks->getArrayCopy());
    }

    /**
     * A grant to a subject locks its grant rows and what it hands out; one to a
     * role, the role's chain; an attachment to a resource, the type's resource
     * policies; each with the tenant it holds in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeLocksWhatItChanges(): void
    {
        $role       = Role::query()->create(['name' => 'editor']);
        $permission = Permission::query()->create(['name' => 'posts:read']);
        $policy     = Policy::query()->create(['name' => 'shared', 'document' => ['statements' => []]]);
        $user       = new Reference(StubIdentity::class, 'user');

        self::assertSame(
            [...self::GRANTS, 'guardrails', 'permissions'],
            $this->tablesLockedFor(OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $user, $permission, GrantScope::platform())),
        );
        self::assertSame(
            ['guardrails', 'roles', 'role_permissions', 'authorizable_policies', 'permissions'],
            $this->tablesLockedFor(OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $role, $permission, GrantScope::platform())),
        );
        self::assertSame(
            ['guardrails', 'resource_policies', 'policies'],
            $this->tablesLockedFor(OperationResource::grant(PackagePermissions::RESOURCE_POLICY_ATTACH, new Reference('post', '*'), $policy, GrantScope::platform())),
        );
        self::assertSame(
            [...self::GRANTS, 'guardrails', 'roles', 'role_permissions', 'authorizable_policies'],
            $this->tablesLockedFor(OperationResource::grant(PackagePermissions::ROLE_GRANT, $user, $role, GrantScope::platform())),
        );
    }

    /**
     * A change to a definition locks the record, a new parent's chain with it;
     * a record not saved yet, or a model of no kind the package stores, locks
     * nothing but the guardrails of the scope.
     *
     * @return void
     */
    public function testADefinitionLocksItsRecordAndANewParent(): void
    {
        $role   = Role::query()->create(['name' => 'editor']);
        $parent = Role::query()->create(['name' => 'senior']);

        $parentSet = OperationResource::definition(PackagePermissions::ROLE_PARENT_SET, $role, ['parent' => $parent->getKey()]);
        $created   = OperationResource::definition(PackagePermissions::ROLE_CREATE, new Role(['name' => 'new']), ['name' => 'new']);
        $foreign   = OperationResource::definition(PackagePermissions::ROLE_UPDATE, StubIdentity::query()->create(['id' => 'model']), []);

        self::assertSame(['guardrails', 'roles', 'role_permissions', 'authorizable_policies'], $this->tablesLockedFor($parentSet));
        self::assertSame(['guardrails'], $this->tablesLockedFor($created));
        self::assertSame(['guardrails'], $this->tablesLockedFor($foreign));

        $locks = $this->recordRowLocks();

        AuthorityRows::in(self::pins(), DependencyPhase::TARGET)->change($parentSet)->lock();

        self::assertSame(self::sorted([$role->getKey(), $parent->getKey()]), $locks[1][1] ?? null);
    }

    /**
     * Return the tables a gathering of the change alone locks, in order.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $change
     * @return list<string>
     */
    private function tablesLockedFor(OperationResource $change): array
    {
        $locks = $this->recordRowLocks();

        AuthorityRows::in(self::pins(), DependencyPhase::TARGET)->change($change)->lock();

        /** @var list<string> */
        return \array_column($locks->getArrayCopy(), 0);
    }

    /**
     * Return the keys sorted, as strings.
     *
     * @param  list<mixed>  $keys
     * @return list<string>
     */
    private static function sorted(array $keys): array
    {
        $keys = \array_map(static fn (mixed $key): string => \is_scalar($key) ? (string) $key : '', $keys);

        \sort($keys, \SORT_STRING);

        return $keys;
    }

    /**
     * Return the pins of a new delegated operation.
     *
     * @return \SineMacula\Laravel\Authorization\Administration\DependencyPins
     */
    private static function pins(): DependencyPins
    {
        return new DependencyPins(new Operation('op', new Reference(StubIdentity::class, 'admin'), CarbonImmutable::now('UTC'), false));
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        /** @var \SineMacula\Laravel\Authorization\Services\GrantService */
        return GrantService::instance();
    }

    /**
     * Return the role service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleService
     */
    private static function roles(): RoleService
    {
        /** @var \SineMacula\Laravel\Authorization\Services\RoleService */
        return RoleService::instance();
    }
}
