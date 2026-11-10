<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use Psr\Log\AbstractLogger;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Concerns\ResolvesPivotExpiry;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\TestCase;

/**
 * Coverage-focused feature tests that reach the narrow branches not hit by the
 * main behavioural suites: relation-loaded unset paths, fallback paths when the
 * resolution cache is unbound, lookup-by-id throws, non-tag cache store
 * branches, empty-string guards on cache keys, and Spatie migration skip
 * branches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 * @SuppressWarnings("php:S112")
 */
#[CoversClass(ResolutionCache::class)]
#[CoversClass(BladeHelpers::class)]
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
#[CoversTrait(HasPolicies::class)]
#[CoversTrait(ResolvesPivotExpiry::class)]
final class UncoveredBranchesTest extends TestCase
{
    /**
     * Loading the roles relation and then calling `assignRole()` must purge the
     * loaded-relation cache so a subsequent read sees the freshly-attached row.
     * Targets the `unset($this->relations['roles'])` branch.
     *
     * @return void
     */
    public function testAssignRoleClearsLoadedRolesRelationCache(): void
    {
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'editor', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Prime the relation cache.
        $user->load('roles');
        self::assertCount(0, $user->roles);

        $user->assignRole($role);

        // Re-reading `$user->roles` hits the freshly-reloaded relation.
        self::assertCount(1, $user->roles);
    }

    /**
     * Same invariant for `syncRoles()` — the relation cache must be purged so a
     * follow-up read sees the new roster.
     *
     * @return void
     */
    public function testSyncRolesClearsLoadedRolesRelationCache(): void
    {
        Role::create(['id' => (string) Str::uuid(), 'name' => 'a', 'guard' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'b', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->load('roles');

        $user->syncRoles(['a', 'b']);

        $names = $user->roles->map(static fn (Role $r): string => $r->name)->all();
        \sort($names);
        self::assertSame(['a', 'b'], $names);
    }

    /**
     * `givePermission()` must clear the loaded-permissions relation cache.
     *
     * @return void
     */
    public function testGivePermissionClearsLoadedPermissionsRelationCache(): void
    {
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard' => 'web']);
        $user       = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->load('permissions');
        self::assertCount(0, $user->permissions);

        $user->givePermission($permission);

        self::assertCount(1, $user->permissions);
    }

    /**
     * `syncPermissions()` must clear the loaded-permissions relation cache.
     *
     * @return void
     */
    public function testSyncPermissionsClearsLoadedPermissionsRelationCache(): void
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'a:do', 'guard' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'b:do', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->load('permissions');

        $user->syncPermissions(['a:do', 'b:do']);

        $names = $user->permissions->map(static fn (Permission $p): string => $p->name)->all();
        \sort($names);
        self::assertSame(['a:do', 'b:do'], $names);
    }

    /**
     * `attachPolicy()` must clear the loaded-policies relation cache.
     *
     * @return void
     */
    public function testAttachPolicyClearsLoadedPoliciesRelationCache(): void
    {
        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'p1',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->load('policies');
        self::assertCount(0, $user->policies);

        $user->attachPolicy($policy);

        self::assertCount(1, $user->policies);
    }

    /**
     * `syncPolicies()` must clear the loaded-policies relation cache.
     *
     * @return void
     */
    public function testSyncPoliciesClearsLoadedPoliciesRelationCache(): void
    {
        $a = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'a',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $b = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'b',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['y']]]],
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->load('policies');

        $user->syncPolicies([$a, $b]);

        self::assertCount(2, $user->policies);
    }

    /**
     * When the resolution cache is not bound to the container, `getRoles()`
     * falls back to `computeRoles()` directly. Targets `HasRoles::getRoles()`
     * line 242.
     *
     * @return void
     */
    public function testGetRolesFallsBackToComputeWhenCacheUnbound(): void
    {
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'viewer', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole($role);

        $this->container()->forgetInstance(ResolutionCache::class);
        $this->container()->offsetUnset(ResolutionCache::class);

        $names = $user->fresh()?->getRoles() ?? [];

        self::assertSame(['viewer'], $names);
    }

    /**
     * When the resolution cache is not bound to the container,
     * `getPermissions()` falls back to `computePermissions()` directly. Targets
     * `HasPermissions::getPermissions()` line 250.
     *
     * @return void
     */
    public function testGetPermissionsFallsBackToComputeWhenCacheUnbound(): void
    {
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:read', 'guard' => 'web']);
        $user       = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission($permission);

        $this->container()->forgetInstance(ResolutionCache::class);
        $this->container()->offsetUnset(ResolutionCache::class);

        $names = $user->fresh()?->getPermissions() ?? [];

        self::assertSame(['posts:read'], $names);
    }

    /**
     * `canActOn()` returns false when the target doesn't expose a `roles()`
     * method. Targets `HasRoles::canActOn()` line 289.
     *
     * @return void
     */
    public function testCanActOnReturnsFalseWhenTargetLacksRolesMethod(): void
    {
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'admin', 'guard' => 'web', 'rank' => 0]);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole($role);

        // A target that implements SupportsRoles but without a real `roles()`
        // relation.
        $target = new class implements SupportsRoles {
            /**
             * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
             * @return static
             */
            #[\Override]
            public function assignRole(Role|string $role): static
            {
                return $this;
            }

            /**
             * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
             * @return static
             */
            #[\Override]
            public function revokeRole(Role|string $role): static
            {
                return $this;
            }

            /**
             * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
             * @return static
             */
            #[\Override]
            public function syncRoles(array $roles): static
            {
                return $this;
            }

            /**
             * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
             * @param  string|null  $guard
             * @return bool
             */
            #[\Override]
            public function hasRole(Role|string $role, ?string $guard = null): bool
            {
                return false;
            }

            /**
             * @return array<int, string>
             */
            #[\Override]
            public function getRoles(): array
            {
                return [];
            }
        };

        self::assertFalse($user->fresh()?->canActOn($target));
    }

    /**
     * `BladeHelpers::hasAllRoles` returns false when the principal does not
     * implement `SupportsRoles`. Targets line 80.
     *
     * @return void
     */
    public function testBladeHelpersHasAllRolesReturnsFalseForNonRoleSupportingPrincipal(): void
    {
        $this->container()->instance(
            SubjectResolver::class,
            new StubSubjectResolver(new \stdClass),
        );

        self::assertFalse(BladeHelpers::hasAllRoles(['admin']));
    }

    // Spatie-migration-specific coverage lives in MigrateSpatieSkipTest; that
    // test suite configures the package tables at `defineEnvironment` time so
    // the `roles` / `permissions` names are free for the Spatie source schema.

    /**
     * `ResolvesPivotExpiry::authorizationCoerceExpiresAt` returns a Carbon
     * instance when the raw pivot value is a non-empty string. Targets lines
     * 135-136 of the trait via a temporal role assignment routed through
     * `getRoles()`.
     *
     * @return void
     */
    public function testCoerceExpiresAtHandlesStringValue(): void
    {
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'temp', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole($role, Carbon::now()->addHour());

        $names = $user->fresh()?->getRoles() ?? [];

        self::assertSame(['temp'], $names);
    }

    /**
     * `logMalformedPolicy` also tolerates a logger that throws on the warning
     * call itself: the logging failure is swallowed and `getPolicies()`
     * rethrows the malformed row's own exception. Targets the outer catch in
     * `HasPolicies::logMalformedPolicy`.
     *
     * @return void
     */
    public function testLogMalformedPolicyTolerantOfLoggerWarningFailure(): void
    {
        // Rebind the logger to one whose `warning()` raises. The method
        // swallows the failure, so the malformed row's own exception is the one
        // that reaches the caller.
        // @phpstan-ignore-next-line method.nonObject
        $this->app->instance('log', new class extends AbstractLogger {
            // @phpstan-ignore method.nonObject
            /**
             * @param  string  $name
             * @return self
             */
            public function channel(string $name): self
            {
                return $this;
            }

            /**
             * @param  string|\Stringable  $message
             * @param  array<mixed>  $context
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function warning(string|\Stringable $message, array $context = []): void
            {
                throw new \RuntimeException('logger unavailable');
            }

            /**
             * @param  mixed  $level
             * @param  string|\Stringable  $message
             * @param  array<mixed>  $context
             * @return void
             */
            #[\Override]
            public function log(mixed $level, string|\Stringable $message, array $context = []): void {}
        });

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'malformed-warn',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $user->attachPolicy($policy);

        // Replace with a JSON payload lacking the `statements` key so
        // `EvaluationPolicy::fromArray()` raises.
        DB::table((string) config('authorization.tables.policies', 'policies')) // @phpstan-ignore cast.string
            ->where('id', $policy->getKey())
            ->update(['document' => \json_encode(['version' => 'not-an-int'])]);

        $this->expectException(InvalidPolicyDocumentException::class);
        $this->expectExceptionMessage('Invalid policy document \'malformed-warn\': Policy document requires a list of statements.');

        $user->fresh()?->getPolicies();
    }
}
