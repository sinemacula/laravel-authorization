<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Exceptions\ReservedRoleNameException;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\RecordsRowLocks;
use Tests\Feature\Stubs\CustomRole;
use Tests\TestCase;

/**
 * Feature tests pinning the role class the observer's hierarchy cycle check
 * resolves.
 *
 * With `authorization.models.role` pointed at an application subclass, the
 * proposed-parent lookup the observer runs before refusing a cycle hydrates
 * that subclass, never the shipped `Role`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RoleObserver::class)]
#[CoversClass(RoleHierarchyCycleException::class)]
#[CoversClass(ReservedRoleNameException::class)]
final class RoleObserverTest extends TestCase
{
    use ActsAsTenant, RecordsRowLocks;

    /** @var array{tenant_type: string, tenant_id: string} The owner columns of a tenant's role. */
    private const array TENANT = ['tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a'];

    /**
     * Point `authorization.models.role` at the subclass stub.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.models.role', CustomRole::class);
    }

    /**
     * Re-parenting a role under its own descendant is refused with the proposed
     * parent's name, read back through the configured subclass.
     *
     * @return void
     */
    public function testCycleCheckLooksUpProposedParentThroughConfiguredRoleClass(): void
    {
        $root  = $this->makeRole('admin');
        $child = $this->makeRole('editor', $root->id);

        $hydrated = $this->recordHydratedRoleClasses();

        $root->parent_id = $child->id;

        try {
            $root->save();
            self::fail('RoleHierarchyCycleException was not thrown.');
        } catch (RoleHierarchyCycleException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('admin', $exception->getRoleName());
            self::assertSame('editor', $exception->getProposedParentName());
            self::assertSame([CustomRole::class], $hydrated->getArrayCopy());
        }
    }

    /**
     * A role is refused as its own parent, named as its own proposed parent.
     *
     * @return void
     */
    public function testARoleCannotBeItsOwnParent(): void
    {
        $role = $this->makeRole('admin');

        $role->parent_id = $role->id;

        $this->expectExceptionObject(new RoleHierarchyCycleException(roleName: 'admin', proposedParentName: 'admin'));

        $role->save();
    }

    /**
     * A parent deeper below the role is refused too, named by the proposed
     * parent rather than the role the walk reached.
     *
     * @return void
     */
    public function testAParentFurtherDownTheHierarchyIsRefused(): void
    {
        $root       = $this->makeRole('root');
        $child      = $this->makeRole('child', $root->id);
        $grandchild = $this->makeRole('grandchild', $child->id);

        $root->parent_id = $grandchild->id;

        $this->expectExceptionObject(new RoleHierarchyCycleException(roleName: 'root', proposedParentName: 'grandchild'));

        $root->save();
    }

    /**
     * The walk reads every ancestor outside the tenant scope, so a cycle
     * through another tenant's role is refused.
     *
     * @return void
     */
    public function testACycleThroughAnotherTenantsRoleIsRefused(): void
    {
        $tenantA = self::createTenant('tenant-a');
        $mine    = CustomRole::query()->create(['name' => 'mine', ...self::ownedBy($tenantA)]);
        $theirs  = CustomRole::query()->create(['name' => 'theirs', ...self::ownedBy(self::createTenant('tenant-b')), 'parent_id' => $mine->id]);
        $middle  = CustomRole::query()->create(['name' => 'middle', ...self::ownedBy($tenantA), 'parent_id' => $theirs->id]);

        $this->actAsTenant($tenantA);

        $mine->parent_id = $middle->id;

        $this->expectExceptionObject(new RoleHierarchyCycleException(roleName: 'mine', proposedParentName: 'middle'));

        $mine->save();
    }

    /**
     * A chain above the proposed parent that loops without reaching the role is
     * corrupt, and the parent is refused rather than walked forever.
     *
     * @return void
     */
    public function testAParentWhoseChainLoopsIsRefused(): void
    {
        $first  = $this->makeRole('first');
        $second = $this->makeRole('second', $first->id);

        Role::query()->whereKey($first->id)->update(['parent_id' => $second->id]);

        $role = $this->makeRole('editor');

        $role->parent_id = $first->id;

        $this->expectExceptionObject(new RoleHierarchyCycleException(roleName: 'editor', proposedParentName: 'first'));

        $role->save();
    }

    /**
     * A role's parent may move to a role outside its descendants.
     *
     * @return void
     */
    public function testAParentOutsideTheRolesDescendantsIsAccepted(): void
    {
        $root    = $this->makeRole('root');
        $child   = $this->makeRole('child', $root->id);
        $another = $this->makeRole('another', $root->id);

        $child->parent_id = $another->id;
        $child->save();

        self::assertSame($another->id, $child->fresh()?->parent_id);
    }

    /**
     * The walk locks each ancestor it reads, in order up the chain.
     *
     * @return void
     */
    public function testTheWalkLocksEachAncestor(): void
    {
        $root   = $this->makeRole('root');
        $parent = $this->makeRole('parent', $root->id);
        $role   = $this->makeRole('editor');

        $locks = $this->recordRowLocks();

        $role->parent_id = $parent->id;
        $role->save();

        self::assertSame([['roles', [$parent->id]], ['roles', [$root->id]]], $locks->getArrayCopy());
    }

    /**
     * A chain that names an ancestor no row answers, as a parent key written
     * past the foreign key would, ends the walk there without an error.
     *
     * @return void
     */
    public function testAChainThatReachesAMissingAncestorEndsTheWalk(): void
    {
        $role            = $this->makeRole('editor');
        $role->parent_id = '00000000-0000-4000-8000-000000000000';

        $locks = $this->recordRowLocks();

        (new RoleObserver)->saving($role);

        self::assertSame([['roles', ['00000000-0000-4000-8000-000000000000']]], $locks->getArrayCopy());
    }

    /**
     * A save that leaves the parent alone does not walk the hierarchy.
     *
     * @return void
     */
    public function testASaveThatLeavesTheParentAloneDoesNotWalk(): void
    {
        $root  = $this->makeRole('root');
        $child = $this->makeRole('child', $root->id);

        $hydrated = $this->recordHydratedRoleClasses();

        $child->description = 'Changed';
        $child->save();

        self::assertSame([], $hydrated->getArrayCopy());
    }

    /**
     * Pairs of a platform role and a tenant role of the same name, by the
     * platform role's guard and system flag and the tenant role's guard, with
     * whether the pair is refused.
     *
     * @return iterable<string, array{string|null, bool, string|null, bool}>
     */
    public static function sharedNames(): iterable
    {
        yield 'system role, same guard' => ['web', true, 'web', true];
        yield 'system role, tenant guard-agnostic' => ['web', true, null, true];
        yield 'guard-agnostic system role' => [null, true, 'web', true];
        yield 'system role, another guard' => ['web', true, 'api', false];
        yield 'ordinary role, same guard' => ['web', false, 'web', false];
    }

    /**
     * A tenant role is refused when it would share its name with a platform
     * system role under a guard both answer.
     *
     * @param  string|null  $platformGuard
     * @param  bool  $isSystem
     * @param  string|null  $tenantGuard
     * @param  bool  $refused
     * @return void
     */
    #[DataProvider('sharedNames')]
    public function testATenantRoleCannotShareTheNameOfAPlatformSystemRole(?string $platformGuard, bool $isSystem, ?string $tenantGuard, bool $refused): void
    {
        CustomRole::query()->create(['name' => 'super-admin', 'guard' => $platformGuard, 'is_system' => $isSystem]);

        self::assertSame($refused, self::isRefused(['name' => 'super-admin', 'guard' => $tenantGuard] + self::TENANT));
        self::assertSame($refused ? 1 : 2, CustomRole::query()->withoutGlobalScopes()->count());
    }

    /**
     * A platform system role is refused when a tenant role already holds its
     * name under a guard both answer.
     *
     * @param  string|null  $platformGuard
     * @param  bool  $isSystem
     * @param  string|null  $tenantGuard
     * @param  bool  $refused
     * @return void
     */
    #[DataProvider('sharedNames')]
    public function testAPlatformSystemRoleCannotTakeATenantRolesName(?string $platformGuard, bool $isSystem, ?string $tenantGuard, bool $refused): void
    {
        CustomRole::query()->create(['name' => 'super-admin', 'guard' => $tenantGuard] + self::TENANT);

        self::assertSame($refused, self::isRefused(['name' => 'super-admin', 'guard' => $platformGuard, 'is_system' => $isSystem]));
    }

    /**
     * The refusal names the role whose save was refused.
     *
     * @return void
     */
    public function testTheRefusalNamesTheRole(): void
    {
        CustomRole::query()->create(['name' => 'super-admin', 'guard' => 'web', 'is_system' => true]);

        try {
            CustomRole::query()->create(['name' => 'super-admin', 'guard' => 'web'] + self::TENANT);
            self::fail('ReservedRoleNameException was not thrown.');
        } catch (ReservedRoleNameException $exception) { // @phpstan-ignore catch.neverThrown
            self::assertSame('super-admin', $exception->getRoleName());
            self::assertSame(
                'Cannot save role \'super-admin\': a tenant role cannot share its name with a platform system role under a guard both answer.',
                $exception->getMessage(),
            );
        }
    }

    /**
     * A tenant role that becomes the platform system role of its own name is
     * not refused because of the row it was.
     *
     * @return void
     */
    public function testARoleIsNeverRefusedBecauseOfItself(): void
    {
        $role = CustomRole::query()->create(['name' => 'super-admin', 'guard' => 'web'] + self::TENANT);

        $role->forceFill(['tenant_type' => null, 'tenant_id' => null, 'is_system' => true])->save();

        self::assertTrue(CustomRole::query()->withoutGlobalScopes()->sole()->is_system);
    }

    /**
     * A save that changes none of the columns the check reads is not checked,
     * so a row that predates the rule can still be edited.
     *
     * @return void
     */
    public function testASaveThatLeavesTheCheckedColumnsAloneIsNotChecked(): void
    {
        $tenantRole = CustomRole::query()->create(['name' => 'super-admin', 'guard' => 'web'] + self::TENANT);

        CustomRole::query()->insert(['id' => '0f6a2c1e-6b2d-4f8a-9e3b-7c1d5a4f2e90', 'name' => 'super-admin', 'guard' => 'web', 'is_system' => true]);

        $tenantRole->description = 'Edited';
        $tenantRole->save();

        self::assertSame('Edited', CustomRole::query()->withoutGlobalScopes()->whereKey($tenantRole->id)->value('description'));
    }

    /**
     * Record the class of every role model hydrated from here on.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordHydratedRoleClasses(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $hydrated */
        $hydrated = new \ArrayObject;

        Event::listen('eloquent.retrieved: *', static function (string $event, array $payload) use ($hydrated): void {
            if (!$payload[0] instanceof Role) {
                return;
            }

            $hydrated->append($payload[0]::class);
        });

        return $hydrated;
    }

    /**
     * Determine whether creating a role with the given attributes is refused
     * for sharing a system role's name.
     *
     * @param  array<string, mixed>  $attributes
     * @return bool
     */
    private static function isRefused(array $attributes): bool
    {
        try {
            CustomRole::query()->create($attributes);
        } catch (ReservedRoleNameException) { // @phpstan-ignore catch.neverThrown
            return true;
        }

        return false;
    }

    /**
     * Create a role through the configured subclass.
     *
     * @param  string  $name
     * @param  string|null  $parentId
     * @return \Tests\Feature\Stubs\CustomRole
     */
    private function makeRole(string $name, ?string $parentId = null): CustomRole
    {
        return CustomRole::query()->create([
            'name'      => $name,
            'guard'     => 'web',
            'parent_id' => $parentId,
        ]);
    }
}
