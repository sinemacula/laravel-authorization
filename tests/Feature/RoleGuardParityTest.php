<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\GuardMismatchException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Models\RolePermission;
use Tests\TestCase;

/**
 * Feature coverage for the role ↔ permission guard-parity rule.
 *
 * Two concrete guards must match; null on either side is the
 * guard-agnostic sentinel and is compatible with every guard. The
 * check lives on the `RolePermission` pivot's `saving` hook, so
 * every attachment path goes through it — the typed API
 * (`$role->givePermission(...)` / `syncPermissions`) and direct
 * relation use (`$role->permissions()->attach(...)` / `sync(...)`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Role::class)]
#[CoversClass(RolePermission::class)]
#[CoversClass(GuardMismatchException::class)]
final class RoleGuardParityTest extends TestCase
{
    /**
     * Matching concrete guards attach cleanly.
     *
     * @return void
     */
    public function testSameGuardAttachmentSucceeds(): void
    {
        $role       = $this->role(guard: 'web');
        $permission = $this->permission(guard: 'web');

        $role->givePermission($permission);

        self::assertTrue($role->fresh()?->hasPermission($permission));
    }

    /**
     * Two concrete but different guards are rejected via the typed
     * Role API.
     *
     * @return void
     */
    public function testCrossGuardAttachmentViaApiIsRejected(): void
    {
        $role       = $this->role(guard: 'web');
        $permission = $this->permission(guard: 'api');

        $this->expectException(GuardMismatchException::class);

        $role->givePermission($permission);
    }

    /**
     * Cross-guard attachment is rejected on the raw relation too
     * — the pivot's `saving` hook catches bypass paths.
     *
     * @return void
     */
    public function testCrossGuardAttachmentViaRawRelationIsRejected(): void
    {
        $role       = $this->role(guard: 'web');
        $permission = $this->permission(guard: 'api');

        $this->expectException(GuardMismatchException::class);

        $role->permissions()->attach($permission->getKey());
    }

    /**
     * Cross-guard attachment via `sync()` is rejected.
     *
     * @return void
     */
    public function testCrossGuardAttachmentViaSyncIsRejected(): void
    {
        $role       = $this->role(guard: 'web');
        $permission = $this->permission(guard: 'api');

        $this->expectException(GuardMismatchException::class);

        $role->permissions()->sync([$permission->getKey()]);
    }

    /**
     * A guard-agnostic permission attaches to a guard-specific
     * role — null on either side is the wildcard.
     *
     * @return void
     */
    public function testGuardAgnosticPermissionAttachesToGuardSpecificRole(): void
    {
        $role       = $this->role(guard: 'web');
        $permission = $this->permission(guard: null);

        $role->givePermission($permission);

        self::assertTrue($role->fresh()?->hasPermission($permission));
    }

    /**
     * A guard-agnostic role accepts a guard-specific permission.
     *
     * @return void
     */
    public function testGuardSpecificPermissionAttachesToGuardAgnosticRole(): void
    {
        $role       = $this->role(guard: null);
        $permission = $this->permission(guard: 'api');

        $role->givePermission($permission);

        self::assertTrue($role->fresh()?->hasPermission($permission));
    }

    /**
     * Both sides guard-agnostic attach cleanly.
     *
     * @return void
     */
    public function testBothGuardAgnosticAttachesSucceeds(): void
    {
        $role       = $this->role(guard: null);
        $permission = $this->permission(guard: null);

        $role->givePermission($permission);

        self::assertTrue($role->fresh()?->hasPermission($permission));
    }

    /**
     * The typed exception carries both names and both guards so
     * audit consumers can report the offending pair without
     * re-querying.
     *
     * @return void
     */
    public function testExceptionCarriesBothNamesAndGuards(): void
    {
        $role       = $this->role(guard: 'web', name: 'editor');
        $permission = $this->permission(guard: 'api', name: 'api:call');

        try {
            $role->givePermission($permission);
            self::fail('Expected GuardMismatchException was not thrown.');
        } catch (GuardMismatchException $exception) {
            self::assertSame('editor', $exception->getRoleName());
            self::assertSame('api:call', $exception->getPermissionName());
            self::assertSame('web', $exception->getRoleGuard());
            self::assertSame('api', $exception->getPermissionGuard());
        }
    }

    /**
     * Build a role with the requested guard and name.
     *
     * @param  string|null  $guard
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private function role(?string $guard, string $name = 'editor'): Role
    {
        return Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => $name,
            'guard_name' => $guard,
        ]);
    }

    /**
     * Build a permission with the requested guard and name.
     *
     * @param  string|null  $guard
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private function permission(?string $guard, string $name = 'posts:create'): Permission
    {
        return Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => $name,
            'guard_name' => $guard,
        ]);
    }
}
