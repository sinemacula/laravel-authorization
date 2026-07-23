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
use SineMacula\Laravel\Authorization\Testing\Concerns\AuthorizationAssertions;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Tests for the shipped testing helpers trait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
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
        Permission::create(['id' => 'c2d9b0b4-d6db-4c09-8e1c-3cc9a9afff14', 'name' => 'docs:view', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => 'c04bbc1e-a3f1-4a00-8a37-5b6ca2de6a88']);
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
        $user = StubIdentity::create(['id' => '9c92e0cb-686f-4347-8ca8-9033eed62375']);

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
        $user = StubIdentity::create(['id' => '10e3747c-3a23-4c42-8245-4f1f6ce2183d']);

        $this->assertCannot($user, 'docs:delete');
    }

    /**
     * `assertCannot` fails when the principal is allowed.
     *
     * @return void
     */
    public function testAssertCannotFailsWhenAllowed(): void
    {
        Permission::create(['id' => 'bf869580-a8d2-4a40-87c7-de6a9d559418', 'name' => 'docs:delete', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '34f13826-645d-4917-81b2-44e93dbf1863']);
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
        Role::create(['id' => 'db35d033-4ec2-49d6-86f2-2e35abb79258', 'name' => 'editor', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '273e3845-88e8-4f96-8c2c-1da012769254']);
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
        $user = StubIdentity::create(['id' => '76018d54-4b6b-4111-8f36-0211bbf0809a']);

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
        Permission::create(['id' => '6d4b70d0-3fed-4b56-8f2e-ee0d7dd8c9cc', 'name' => 'docs:edit', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '6160c26b-9f8d-437b-8e39-bc3fcef72076']);
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
        $user = StubIdentity::create(['id' => 'f67a151d-b31d-4c6c-8d79-097b54709b8d']);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessageMatches('/Failed asserting that the principal has permission \'docs:edit\'/');

        $this->assertHasPermission($user, 'docs:edit');
    }

    /**
     * `actingAsIdentity` swaps the resolver so the facade works without
     * explicit `for()`.
     *
     * @return void
     */
    public function testActingAsIdentitySwapsResolver(): void
    {
        Permission::create(['id' => 'f663ff0d-9a15-49bd-8234-d30ac5b91f73', 'name' => 'docs:publish', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '5f5924a2-a361-4d9a-8ea6-f24ecbc25de1']);
        $user->givePermission('docs:publish');

        // Before swap, anonymous principal is denied.
        self::assertFalse(Authorization::can('docs:publish'));

        $this->actingAsIdentity($user);

        // After swap, the facade resolves the swapped principal.
        self::assertTrue(Authorization::can('docs:publish'));
    }

    /**
     * `assertCan` includes the resource in its failure message when one is
     * supplied.
     *
     * @return void
     */
    public function testAssertCanIncludesResourceInFailureMessage(): void
    {
        $user = StubIdentity::create(['id' => '53e9833c-b3d7-4ecf-845e-616b486a1677']);

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
        $user = StubIdentity::create(['id' => 'e95a40aa-3f8b-4137-8d8a-71879a3c0dcb']);

        $user->attachPolicy(Policy::create([
            'id'       => 'd9b1e409-7edc-4807-879c-6301100ecd3f',
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
