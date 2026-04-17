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
        Permission::create(['id' => '01JEFFPERM000000000000001', 'name' => 'posts:create', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '01JEFFPERM00000000000USR1']);
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
        $role       = Role::create(['id' => '01JEFFPERM00000000000ROL1', 'name' => 'editor', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => '01JEFFPERM000000000000002', 'name' => 'posts:create', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $user = StubIdentity::create(['id' => '01JEFFPERM00000000000USR2']);
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
        Permission::create(['id' => '01JEFFPERM000000000000003', 'name' => 'posts:delete', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '01JEFFPERM00000000000USR3']);
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

        $user = StubIdentity::create(['id' => '01JEFFPERM00000000000USR4']);

        $effective = Authorization::for($user)->effectivePermissions();

        self::assertSame([], $effective);
    }
}
