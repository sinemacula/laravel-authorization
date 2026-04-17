<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the effective-permissions API.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationManager::class)]
final class EffectivePermissionsTest extends TestCase
{
    /**
     * Register the permission enum before each test.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);
    }

    /**
     * Direct grant yields true in the effective map.
     *
     * @return void
     */
    public function testDirectGrantShowsTrueInEffectiveMap(): void
    {
        Permission::create(['id' => '6e0d87a1-a966-4767-8c29-2e0075b7b4e2', 'name' => 'posts:create', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '4eaa47a6-4a3a-488d-8d0a-2082bb056ec0']);
        $user->givePermission('posts:create');

        $effective = Authorization::for($user)->effectivePermissions();

        self::assertArrayHasKey('posts:create', $effective);
        self::assertTrue($effective['posts:create']);
        self::assertArrayHasKey('posts:delete', $effective);
        self::assertFalse($effective['posts:delete']);
    }

    /**
     * Role-inherited permission yields true.
     *
     * @return void
     */
    public function testRoleInheritedPermissionShowsTrueInEffectiveMap(): void
    {
        $role       = Role::create(['id' => 'c3af7a8c-6e21-4cf2-88a3-36175d9060b2', 'name' => 'editor', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => 'daf362a8-707d-4446-80db-7e5525abcdea', 'name' => 'posts:create', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $user = StubIdentity::create(['id' => '7c747a9a-f770-4e3e-8a33-e4d401f1d76b']);
        $user->assignRole('editor');

        $effective = Authorization::for($user)->effectivePermissions();

        self::assertTrue($effective['posts:create']);
    }

    /**
     * Explicit deny policy overrides a direct grant in the effective
     * map.
     *
     * @return void
     */
    public function testExplicitDenyPolicyOverridesDirectGrant(): void
    {
        Permission::create(['id' => '81d87da5-61fb-4a82-8773-9878ae064d11', 'name' => 'posts:delete', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '9813af0f-b8a4-44d3-8d9b-a1f5400dfc07']);
        $user->givePermission('posts:delete');

        $user->attachPolicy(Policy::create([
            'id'       => 'b78828f3-bd2c-4143-8635-8597e0e03300',
            'name'     => 'deny-posts-delete',
            'document' => [
                'statements' => [
                    ['effect' => 'deny', 'actions' => ['posts:delete']],
                ],
            ],
        ]));

        $effective = Authorization::for($user)->effectivePermissions();

        self::assertFalse($effective['posts:delete']);
    }

    /**
     * Anonymous principal returns all-false.
     *
     * @return void
     */
    public function testAnonymousPrincipalReturnsAllFalse(): void
    {
        $effective = Authorization::effectivePermissions();

        self::assertCount(2, $effective);

        foreach ($effective as $allowed) {
            self::assertFalse($allowed);
        }
    }

    /**
     * Effective permissions with no enums configured returns empty.
     *
     * @return void
     */
    public function testEmptyEnumsReturnsEmptyMap(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', []);

        $user = StubIdentity::create(['id' => '327dffb4-192c-485f-810c-169d121b9f73']);

        $effective = Authorization::for($user)->effectivePermissions();

        self::assertSame([], $effective);
    }
}
