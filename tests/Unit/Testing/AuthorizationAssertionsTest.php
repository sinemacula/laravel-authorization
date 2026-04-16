<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Testing\AuthorizationAssertions;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Tests for the shipped testing helpers trait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationManager::class)]
#[CoversTrait(AuthorizationAssertions::class)]
final class AuthorizationAssertionsTest extends TestCase
{
    use AuthorizationAssertions;

    /**
     * `assertCan` passes when the principal holds the permission.
     *
     * @return void
     */
    public function testAssertCanPassesWhenAllowed(): void
    {
        Permission::create(['id' => '01JASSERT00000000000000001', 'name' => 'docs:view', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '01JASSERT00000000000000USR']);
        $user->givePermission('docs:view');

        $this->assertCan($user, 'docs:view');
    }

    /**
     * `assertCan` fails with a trace-bearing message when denied.
     *
     * @return void
     */
    public function testAssertCanFailsWithTraceOnDeny(): void
    {
        $user = StubIdentity::create(['id' => '01JASSERT0000000000000USR2']);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/Failed asserting that the principal can perform/');

        $this->assertCan($user, 'docs:view');
    }

    /**
     * `assertCannot` passes when the principal is denied.
     *
     * @return void
     */
    public function testAssertCannotPassesWhenDenied(): void
    {
        $user = StubIdentity::create(['id' => '01JASSERT0000000000000USR3']);

        $this->assertCannot($user, 'docs:delete');
    }

    /**
     * `assertCannot` fails when the principal is allowed.
     *
     * @return void
     */
    public function testAssertCannotFailsWhenAllowed(): void
    {
        Permission::create(['id' => '01JASSERT00000000000000002', 'name' => 'docs:delete', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '01JASSERT0000000000000USR4']);
        $user->givePermission('docs:delete');

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/Failed asserting that the principal cannot perform/');

        $this->assertCannot($user, 'docs:delete');
    }

    /**
     * `assertHasRole` passes when the role is assigned.
     *
     * @return void
     */
    public function testAssertHasRolePassesWhenAssigned(): void
    {
        Role::create(['id' => '01JASSERT00000000000000ROL', 'name' => 'editor', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '01JASSERT0000000000000USR5']);
        $user->assignRole('editor');

        $this->assertHasRole($user, 'editor');
    }

    /**
     * `assertHasRole` fails when the role is not assigned.
     *
     * @return void
     */
    public function testAssertHasRoleFailsWhenMissing(): void
    {
        $user = StubIdentity::create(['id' => '01JASSERT0000000000000USR6']);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/Failed asserting that the principal has role \'admin\'/');

        $this->assertHasRole($user, 'admin');
    }

    /**
     * `assertHasPermission` passes when the permission is held.
     *
     * @return void
     */
    public function testAssertHasPermissionPassesWhenHeld(): void
    {
        Permission::create(['id' => '01JASSERT00000000000000003', 'name' => 'docs:edit', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '01JASSERT0000000000000USR7']);
        $user->givePermission('docs:edit');

        $this->assertHasPermission($user, 'docs:edit');
    }

    /**
     * `assertHasPermission` fails when the permission is not held.
     *
     * @return void
     */
    public function testAssertHasPermissionFailsWhenMissing(): void
    {
        $user = StubIdentity::create(['id' => '01JASSERT0000000000000USR8']);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/Failed asserting that the principal has permission \'docs:edit\'/');

        $this->assertHasPermission($user, 'docs:edit');
    }

    /**
     * `actingAsIdentity` swaps the resolver so the facade works
     * without explicit `for()`.
     *
     * @return void
     */
    public function testActingAsIdentitySwapsResolver(): void
    {
        Permission::create(['id' => '01JASSERT00000000000000004', 'name' => 'docs:publish', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '01JASSERT0000000000000USR9']);
        $user->givePermission('docs:publish');

        // Before swap, anonymous principal is denied.
        self::assertFalse(Authorization::can('docs:publish'));

        $this->actingAsIdentity($user);

        // After swap, the facade resolves the swapped principal.
        self::assertTrue(Authorization::can('docs:publish'));
    }

    /**
     * `assertCan` includes the resource in its failure message when
     * one is supplied.
     *
     * @return void
     */
    public function testAssertCanIncludesResourceInFailureMessage(): void
    {
        $user = StubIdentity::create(['id' => '01JASSERT000000000000USR10']);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/on resource \'post:42\'/');

        $this->assertCan($user, 'posts:edit', 'post:42');
    }

    /**
     * `assertCan` passes when allowed via policy with resource context.
     *
     * @return void
     */
    public function testAssertCanPassesWithResourceAndContext(): void
    {
        $user = StubIdentity::create(['id' => '01JASSERT000000000000USR11']);

        $user->attachPolicy(Policy::create([
            'id'       => '01JASSERT0000000000000POL1',
            'name'     => 'scoped-allow',
            'document' => [
                'statements' => [[
                    'effect'     => 'allow',
                    'actions'    => ['posts:edit'],
                    'resources'  => ['post:42'],
                    'conditions' => ['tenant' => ['eq' => 'org-1']],
                ]],
            ],
        ]));

        $this->assertCan($user, 'posts:edit', 'post:42', ['tenant' => 'org-1']);
        $this->assertCannot($user, 'posts:edit', 'post:42', ['tenant' => 'org-2']);
    }
}
