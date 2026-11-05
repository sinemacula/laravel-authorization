<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyDetached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\CustomRole;
use Tests\Feature\Stubs\StubIdentity;
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
     * carrying the grantee, the target and the expiries.
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
        $model    = $target();
        $grantee  = new StubIdentity(['id' => 'user-1']);
        $previous = Carbon::parse('2026-07-01 12:00:00', 'UTC');
        $next     = Carbon::parse('2026-08-01 12:00:00', 'UTC');

        $grantedEvent = $kind->grantedEvent($grantee, $model);
        $revokedEvent = $kind->revokedEvent($grantee, $model);
        $changedEvent = $kind->expiryChangedEvent($grantee, $model, $previous, $next);

        self::assertInstanceOf($granted, $grantedEvent);
        self::assertInstanceOf($revoked, $revokedEvent);
        self::assertInstanceOf($expiryChanged, $changedEvent);
        self::assertEquals([$grantee, $model], \array_values((array) $grantedEvent));
        self::assertEquals([$grantee, $model], \array_values((array) $revokedEvent));
        self::assertEquals([$grantee, $model, $previous, $next], \array_values((array) $changedEvent));
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
