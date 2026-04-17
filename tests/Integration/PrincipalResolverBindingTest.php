<?php

declare(strict_types = 1);

namespace Tests\Integration;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Integration coverage for custom `PrincipalResolver` bindings.
 *
 * Confirms that a host-application-supplied resolver flows through
 * the facade end-to-end: the manager consults it on every call,
 * null resolution degrades to an implicit deny, and rebinding the
 * contract between evaluations is honoured by the manager
 * singleton once the container instance is flushed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationManager::class)]
final class PrincipalResolverBindingTest extends TestCase
{
    /** Permission string exercised by the happy-path / null-resolver scenarios. */
    private const string PUBLISH_PERMISSION = 'posts:publish';

    /** Permission granted to the first user in the swap scenario. */
    private const string VIEW_REPORTS_PERMISSION = 'reports:view';

    /** Permission granted to the second user in the swap scenario. */
    private const string EXPORT_REPORTS_PERMISSION = 'reports:export';

    /**
     * A custom resolver returning a real user is consulted by the
     * facade and decisions honour the user's permissions.
     *
     * @return void
     */
    public function testCustomResolverUserFlowsThroughFacade(): void
    {
        $user = $this->makeIdentityWithPermission(self::PUBLISH_PERMISSION);

        $this->bindResolverReturning($user);

        self::assertTrue(Authorization::can(self::PUBLISH_PERMISSION));
        self::assertFalse(Authorization::can('posts:delete'));
    }

    /**
     * A custom resolver returning null produces an implicit deny on
     * every facade call regardless of permissions persisted on
     * other identities.
     *
     * @return void
     */
    public function testNullResolverYieldsImplicitDeny(): void
    {
        // Seed a user whose permissions should NEVER be consulted,
        // proving the null resolver short-circuits the evaluator.
        $this->makeIdentityWithPermission(self::PUBLISH_PERMISSION);

        $this->bindResolverReturning(null);

        self::assertFalse(Authorization::can(self::PUBLISH_PERMISSION));
        self::assertFalse(Authorization::can('anything:at-all'));
    }

    /**
     * Swapping the resolver between evaluations is honoured by the
     * manager singleton once the container instance is flushed and
     * the facade's cached resolution is cleared.
     *
     * @return void
     */
    public function testResolverSwapMidRequestIsHonouredByManagerSingleton(): void
    {
        $first  = $this->makeIdentityWithPermission(self::VIEW_REPORTS_PERMISSION, id: '48a03f8a-ca3c-4605-8bae-6dee34e05da0');
        $second = $this->makeIdentityWithPermission(self::EXPORT_REPORTS_PERMISSION, id: '8d041bf6-f7ea-4515-8e48-28ecf95dee37');

        $this->bindResolverReturning($first);

        self::assertTrue(Authorization::can(self::VIEW_REPORTS_PERMISSION));
        self::assertFalse(Authorization::can(self::EXPORT_REPORTS_PERMISSION));

        // Swap the resolver — the next evaluation must pick up the
        // new subject.
        $this->bindResolverReturning($second);

        self::assertFalse(Authorization::can(self::VIEW_REPORTS_PERMISSION));
        self::assertTrue(Authorization::can(self::EXPORT_REPORTS_PERMISSION));
    }

    /**
     * Bind a resolver that returns the supplied principal and flush
     * every cached handle to the manager so the next facade call
     * reconstructs it against the new binding.
     *
     * @param  object|null  $principal
     * @return void
     */
    private function bindResolverReturning(?object $principal): void
    {
        $resolver = new class ($principal) implements PrincipalResolver {
            /**
             * Create a new resolver wrapping a fixed principal.
             *
             * @param  object|null  $principal
             * @return void
             */
            public function __construct(

                /** The principal returned by every resolution call. */
                private readonly ?object $principal,

            ) {}

            /**
             * Resolve the principal, which may be null.
             *
             * @return object|null
             */
            #[\Override]
            public function resolve(): ?object
            {
                return $this->principal;
            }
        };

        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        $app->instance(PrincipalResolver::class, $resolver);
        $app->forgetInstance('authorization');
        $app->forgetInstance(AuthorizationManager::class);
        Authorization::clearResolvedInstance('authorization');
    }

    /**
     * Create a stub identity holding a direct permission grant.
     *
     * @param  string  $permission
     * @param  string|null  $id
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function makeIdentityWithPermission(string $permission, ?string $id = null): StubIdentity
    {
        $role = Role::create([
            'id'         => 'role-' . \md5($permission),
            'name'       => 'role-' . $permission,
            'guard_name' => 'web',
        ]);

        $permissionModel = Permission::create([
            'id'         => 'perm-' . \md5($permission),
            'name'       => $permission,
            'guard_name' => 'web',
        ]);

        $role->permissions()->attach($permissionModel->getKey());

        $user = StubIdentity::create([
            'id' => $id ?? ('usr-' . \md5($permission)),
        ]);

        $user->assignRole($role);

        return $user;
    }
}
