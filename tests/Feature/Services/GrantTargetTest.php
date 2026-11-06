<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpired;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyDetached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpired;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpired;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\GrantChange;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\CustomRole;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for `GrantTarget`, the kinds of row a grantee can be granted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantTarget::class)]
final class GrantTargetTest extends TestCase
{
    use ActsAsTenant;

    /**
     * The grant table, column and relation of each kind.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Authorization\Enums\GrantTarget, string, string, string}>
     */
    public static function kinds(): iterable
    {
        yield 'role' => [GrantTarget::ROLE, 'authorizable_roles', 'role_id', 'roles'];
        yield 'permission' => [GrantTarget::PERMISSION, 'authorizable_permissions', 'permission_id', 'permissions'];
        yield 'policy' => [GrantTarget::POLICY, 'authorizable_policies', 'policy_id', 'policies'];
    }

    /**
     * Each kind names its grant table, the column that names the granted row
     * and the grantee's relation.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  string  $table
     * @param  string  $column
     * @param  string  $relation
     * @return void
     */
    #[DataProvider('kinds')]
    public function testNamesItsTableColumnAndRelation(GrantTarget $kind, string $table, string $column, string $relation): void
    {
        self::assertSame($table, $kind->table());
        self::assertSame($column, $kind->column());
        self::assertSame($relation, $kind->relation());
    }

    /**
     * The grant table is read from `authorization.tables`.
     *
     * @return void
     */
    public function testReadsTheConfiguredTable(): void
    {
        $this->config()->set('authorization.tables.authorizable_policies', 'auth_policy_grants');

        self::assertSame('auth_policy_grants', GrantTarget::POLICY->table());
    }

    /**
     * A name resolves to the row the lookup ranks first under the guard, the
     * guard-specific row before a guard-agnostic one.
     *
     * @return void
     */
    public function testResolvesANameUnderTheGuard(): void
    {
        Role::query()->create(['name' => 'editor']);
        $api = Role::query()->create(['name' => 'editor', 'guard' => 'api']);
        $web = Role::query()->create(['name' => 'editor', 'guard' => 'web']);

        self::assertTrue($api->is(GrantTarget::ROLE->resolve('editor', 'api')));
        self::assertTrue($web->is(GrantTarget::ROLE->resolve('editor', null)));
    }

    /**
     * With no guard, a name is looked up under the configured default guard.
     *
     * @return void
     */
    public function testResolvesANameUnderTheConfiguredDefaultGuard(): void
    {
        $this->config()->set('authorization.defaults.guard', 'api');

        Role::query()->create(['name' => 'editor', 'guard' => 'web']);
        $api = Role::query()->create(['name' => 'editor', 'guard' => 'api']);

        self::assertTrue($api->is(GrantTarget::ROLE->resolve('editor', null)));
    }

    /**
     * A name is looked up through the configured model class.
     *
     * @return void
     */
    public function testResolvesANameThroughTheConfiguredClass(): void
    {
        $this->config()->set('authorization.models.role', CustomRole::class);

        Role::query()->create(['name' => 'editor']);

        self::assertInstanceOf(CustomRole::class, GrantTarget::ROLE->resolve('editor', null));
    }

    /**
     * A model of the kind resolves to itself.
     *
     * @return void
     */
    public function testResolvesAModelToItself(): void
    {
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        self::assertSame($permission, GrantTarget::PERMISSION->resolve($permission, null));
    }

    /**
     * `named()` returns every row of the name, in the order the lookup ranks
     * them.
     *
     * @return void
     */
    public function testNamedReturnsEveryRowOfTheName(): void
    {
        $agnostic = Permission::query()->create(['name' => 'posts:edit']);
        $web      = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'web']);

        self::assertSame([$web->id, $agnostic->id], \array_map(static fn ($model): mixed => $model->getKey(), GrantTarget::PERMISSION->named('posts:edit', 'web')));
    }

    /**
     * Given a tenant, a name answers the rows visible there, the tenant's own
     * first, and `heldOrFirst()` and `resolve()` read the same rows.
     *
     * @return void
     */
    public function testANameAnswersTheRowsOfTheTenantNamed(): void
    {
        $tenant   = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);
        $platform = Role::query()->create(['name' => 'editor']);
        $owned    = Role::query()->create(['name' => 'editor', 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => 'tenant-a']);
        $scope    = new Reference($tenant->getMorphClass(), 'tenant-a');
        $keys     = static fn (array $models): array => \array_map(static fn ($model): mixed => $model->getKey(), $models);

        self::assertSame([$owned->id, $platform->id], $keys(GrantTarget::ROLE->named('editor', null, $scope)));
        self::assertSame([$platform->id], $keys(GrantTarget::ROLE->named('editor', null)));
        self::assertSame([$platform->id], $keys(GrantTarget::ROLE->heldOrFirst('editor', null, [$platform->id], $scope)));
        self::assertSame($owned->id, GrantTarget::ROLE->resolve('editor', null, $scope)->getKey());
    }

    /**
     * `heldOrFirst()` returns every held row of the name, in the order the
     * lookup ranks them, and the first row only when none is held.
     *
     * @return void
     */
    public function testHeldOrFirstKeepsTheHeldRowsOfTheName(): void
    {
        $agnostic = Permission::query()->create(['name' => 'posts:edit']);
        $web      = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'web']);
        $api      = Permission::query()->create(['name' => 'posts:edit', 'guard' => 'api']);
        $keys     = static fn (array $models): array => \array_map(static fn ($model): mixed => $model->getKey(), $models);

        self::assertSame([$agnostic->id], $keys(GrantTarget::PERMISSION->heldOrFirst('posts:edit', 'web', [$agnostic->id, $api->id])));
        self::assertSame([$web->id, $agnostic->id], $keys(GrantTarget::PERMISSION->heldOrFirst('posts:edit', 'web', [$agnostic->id, $web->id])));
        self::assertSame([$web->id], $keys(GrantTarget::PERMISSION->heldOrFirst('posts:edit', 'web', [$api->id])));
        self::assertSame([$web->id], $keys(GrantTarget::PERMISSION->heldOrFirst('posts:edit', 'web', [])));
    }

    /**
     * An unknown role name throws `UnknownRoleException`.
     *
     * @return void
     */
    public function testAnUnknownRoleNameThrows(): void
    {
        $this->expectExceptionObject(new UnknownRoleException('ghost'));

        GrantTarget::ROLE->named('ghost', null);
    }

    /**
     * An unknown permission name throws `UnknownPermissionException`.
     *
     * @return void
     */
    public function testAnUnknownPermissionNameThrows(): void
    {
        $this->expectExceptionObject(new UnknownPermissionException('ghost'));

        GrantTarget::PERMISSION->named('ghost', null);
    }

    /**
     * A policy is never named.
     *
     * @return void
     */
    public function testAPolicyIsNeverNamed(): void
    {
        $this->expectExceptionObject(new InvalidGrantTargetException('policy', 'audit'));

        GrantTarget::POLICY->resolve('audit', null);
    }

    /**
     * Targets that are not a saved model of the kind.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Authorization\Enums\GrantTarget, \Closure(): mixed}>
     */
    public static function refusedTargets(): iterable
    {
        yield 'a role for a permission grant' => [GrantTarget::PERMISSION, static fn (): mixed => Role::query()->create(['name' => 'editor'])];
        yield 'an identity for a policy grant' => [GrantTarget::POLICY, static fn (): mixed => StubIdentity::query()->create(['id' => 'user-1'])];
        yield 'an unsaved role' => [GrantTarget::ROLE, static fn (): mixed => new Role(['name' => 'editor'])];
        yield 'an integer' => [GrantTarget::ROLE, static fn (): mixed => 42];
    }

    /**
     * Anything that is not a saved model of the kind is refused.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Closure(): mixed  $target
     * @return void
     */
    #[DataProvider('refusedTargets')]
    public function testRefusesATargetThatIsNotASavedModelOfTheKind(GrantTarget $kind, \Closure $target): void
    {
        $value = $target();

        $this->expectExceptionObject(new InvalidGrantTargetException($kind->value, $value));

        $kind->assertTarget($value);
    }

    /**
     * A saved model of the configured subclass is accepted.
     *
     * @return void
     */
    public function testAcceptsASavedModelOfTheConfiguredSubclass(): void
    {
        $this->config()->set('authorization.models.role', CustomRole::class);

        $role = CustomRole::query()->create(['name' => 'editor']);

        self::assertSame($role, GrantTarget::ROLE->assertTarget($role));
    }

    /**
     * `find()` loads rows outside the tenant scope, through the configured
     * class.
     *
     * @return void
     */
    public function testFindReadsOutsideTheTenantScope(): void
    {
        $this->config()->set('authorization.models.role', CustomRole::class);

        $tenant = self::createTenant('tenant-a');
        $role   = Role::query()->create(['name' => 'editor', ...self::ownedBy($tenant)]);

        $this->actAsTenant(self::createTenant('tenant-b'));

        $found = GrantTarget::ROLE->find([$role->id]);

        self::assertCount(1, $found);
        self::assertInstanceOf(CustomRole::class, $found[0]);
        self::assertSame($role->id, $found[0]->getKey());
    }

    /**
     * The events each kind dispatches.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{\SineMacula\Laravel\Authorization\Enums\GrantTarget, \Closure(): \Illuminate\Database\Eloquent\Model, class-string, class-string, class-string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    public static function events(): iterable
    {
        $role       = static fn () => Role::query()->create(['name' => 'editor']);
        $permission = static fn () => Permission::query()->create(['name' => 'posts:edit']);
        $policy     = static fn () => Policy::query()->create(['name' => 'audit', 'document' => ['statements' => []]]);

        yield 'role' => [GrantTarget::ROLE, $role, RoleAssigned::class, RoleRevoked::class, RoleExpiryChanged::class];
        yield 'permission' => [GrantTarget::PERMISSION, $permission, PermissionGranted::class, PermissionRevoked::class, PermissionExpiryChanged::class];
        yield 'policy' => [GrantTarget::POLICY, $policy, PolicyAttached::class, PolicyDetached::class, PolicyExpiryChanged::class];
    }

    /**
     * Each kind builds its own granted, revoked and expiry-changed events,
     * carrying the grantee, the target, the scope and the expiries.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \Closure(): \Illuminate\Database\Eloquent\Model  $target
     * @param  class-string  $granted
     * @param  class-string  $revoked
     * @param  class-string  $expiryChanged
     * @return void
     */
    #[DataProvider('events')]
    public function testBuildsTheEventsOfItsKind(GrantTarget $kind, \Closure $target, string $granted, string $revoked, string $expiryChanged): void
    {
        $model     = $target();
        $operation = Operation::begin(new Reference('user', 'admin-1'));
        $grantee   = new Reference('stub_identity', 'user-1');
        $previous  = Carbon::parse('2026-07-01 14:00:00', 'Europe/Paris');
        $next      = Carbon::parse('2026-08-01 12:00:00', 'UTC');
        $target    = Reference::of($model);
        $name      = $model->getAttribute('name');
        $scope     = new GrantScope(new Reference('stub_tenant', 'tenant-a'));

        $grantedEvent = $kind->grantedEvent($operation, $grantee, $model, $scope, $next);
        $revokedEvent = $kind->revokedEvent($operation, $grantee, $model, $scope);
        $changedEvent = $kind->expiryChangedEvent($operation, $grantee, $model, $scope, $previous, null);

        self::assertInstanceOf($granted, $grantedEvent);
        self::assertInstanceOf($revoked, $revokedEvent);
        self::assertInstanceOf($expiryChanged, $changedEvent);
        self::assertEquals(
            [$operation, $grantee, $target, $name, $scope, new \DateTimeImmutable('2026-08-01 12:00:00', new \DateTimeZone('UTC'))],
            \array_values((array) $grantedEvent),
        );
        self::assertEquals([$operation, $grantee, $target, $name, $scope], \array_values((array) $revokedEvent));
        self::assertEquals(
            [$operation, $grantee, $target, $name, $scope, new \DateTimeImmutable('2026-07-01 12:00:00', new \DateTimeZone('UTC')), null],
            \array_values((array) $changedEvent),
        );
        self::assertSame('UTC', $changedEvent->previousExpiresAt?->getTimezone()->getName()); // @phpstan-ignore property.notFound
    }

    /**
     * Each kind builds its own expired event, carrying the grantee, the target,
     * the scope and the expiry in UTC.
     *
     * @return void
     */
    public function testBuildsTheExpiredEventOfEachKind(): void
    {
        $operation = Operation::begin();
        $grantee   = new Reference('stub_identity', 'user-1');
        $scope     = GrantScope::platform();
        $expiredAt = Carbon::parse('2026-07-01 14:00:00', 'Europe/Paris');
        $targets   = [
            [GrantTarget::ROLE, Role::query()->create(['name' => 'editor']), RoleExpired::class],
            [GrantTarget::PERMISSION, Permission::query()->create(['name' => 'posts:edit']), PermissionExpired::class],
            [GrantTarget::POLICY, Policy::query()->create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]), PolicyExpired::class],
        ];

        foreach ($targets as [$kind, $model, $class]) {
            $event = $kind->expiredEvent($operation, $grantee, $model, $scope, $expiredAt);

            self::assertInstanceOf($class, $event);
            self::assertEquals(
                [$operation, $grantee, Reference::of($model), $model->getAttribute('name'), $scope, new \DateTimeImmutable('2026-07-01 12:00:00', new \DateTimeZone('UTC'))],
                \array_values((array) $event),
            );
        }
    }

    /**
     * A grant's change dispatches nothing when unchanged, the granted event
     * when new or its reach changed, and the granted and expiry-changed events
     * when re-armed or changed.
     *
     * @return void
     */
    public function testBuildsTheEventsOfAChange(): void
    {
        $role      = Role::query()->create(['name' => 'editor']);
        $operation = Operation::begin();
        $grantee   = new Reference('stub_identity', 'user-1');
        $scope     = GrantScope::platform();
        $previous  = Carbon::parse('2026-07-01 12:00:00', 'UTC');
        $classes   = static fn (GrantOutcome $outcome): array => \array_map(
            static fn (object $event): string => $event::class,
            GrantTarget::ROLE->changeEvents($operation, $grantee, $role, $scope, new GrantChange($outcome, $previous), null),
        );

        self::assertSame([], $classes(GrantOutcome::UNCHANGED));
        self::assertSame([RoleAssigned::class], $classes(GrantOutcome::GRANTED));
        self::assertSame([RoleAssigned::class], $classes(GrantOutcome::REACH_CHANGED));
        self::assertSame([RoleAssigned::class, RoleExpiryChanged::class], $classes(GrantOutcome::REARMED));
        self::assertSame([RoleAssigned::class, RoleExpiryChanged::class], $classes(GrantOutcome::EXPIRY_CHANGED));
    }

    /**
     * The holders of a row are every grantee that holds it, once each, in any
     * scope and whether or not the grant has expired, ordered by type and key.
     *
     * @return void
     */
    public function testListsEveryHolderOfARowOnceInOrder(): void
    {
        $role  = Role::query()->create(['name' => 'editor']);
        $other = Role::query()->create(['name' => 'author']);
        $rows  = [
            ['user', '2', null, null],
            ['user', '2', 'stub_tenant', 'tenant-a'],
            ['admin', '1', null, null],
            ['user', '10', null, null],
        ];

        foreach ($rows as [$type, $id, $tenantType, $tenantId]) {
            DB::table('authorizable_roles')->insert([
                'role_id'           => $role->id,
                'authorizable_type' => $type,
                'authorizable_id'   => $id,
                'tenant_type'       => $tenantType,
                'tenant_id'         => $tenantId,
                'expires_at'        => '2020-01-01 00:00:00',
            ]);
        }

        DB::table('authorizable_roles')->insert(['role_id' => $other->id, 'authorizable_type' => 'user', 'authorizable_id' => '3']);

        self::assertEquals([new Reference('admin', '1'), new Reference('user', '10'), new Reference('user', '2')], GrantTarget::ROLE->holders($role->id));
        self::assertSame([], GrantTarget::PERMISSION->holders($role->id));
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
