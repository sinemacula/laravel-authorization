<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\Narrowing;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `Narrowing`, which tells whether removing a grant can only
 * narrow authority.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Narrowing::class)]
final class NarrowingTest extends TestCase
{
    /**
     * Revoking a permission always narrows; removing a boundary never does, nor
     * does any action that is not a removal, nor a removal of a target of
     * another kind.
     *
     * @return void
     */
    public function testAPermissionRevocationNarrowsAndABoundaryRemovalNever(): void
    {
        $permission = Permission::create(['name' => 'posts:edit']);
        $allowing   = self::policy('allowing', 'allow');

        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::PERMISSION_REVOKE, $permission));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::BOUNDARY_REMOVE, $allowing));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::PERMISSION_GRANT, $permission));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $permission));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::POLICY_DETACH, $permission));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::RESOURCE_POLICY_DETACH, $permission));
    }

    /**
     * Detaching a policy, from a grantee or a resource, narrows when the policy
     * as stored has no deny statement; one that denies, one whose document
     * cannot be read and one that is gone do not.
     *
     * @return void
     */
    public function testDetachingAnAllowOnlyPolicyNarrows(): void
    {
        $allowing = self::policy('allowing', 'allow');
        $denying  = self::policy('denying', 'deny');
        $broken   = self::policy('broken', 'allow');

        DB::table('policies')->where('id', $broken->id)->update(['document' => '{"statements": "not a list"}']);

        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::POLICY_DETACH, $allowing));
        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::RESOURCE_POLICY_DETACH, $allowing));
        self::assertTrue(Narrowing::isAllowOnly($allowing));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::POLICY_DETACH, $denying));
        self::assertFalse(Narrowing::isAllowOnly($broken));
        self::assertFalse(Narrowing::isAllowOnly(new Policy(['name' => 'unsaved'])));
    }

    /**
     * The policy judged is the one stored, never the model as the caller holds
     * it.
     *
     * @return void
     */
    public function testThePolicyIsJudgedAsStored(): void
    {
        $policy = self::policy('allowing', 'allow');

        DB::table('policies')->where('id', $policy->id)->update(['document' => \json_encode(['statements' => [['effect' => 'deny', 'actions' => ['*']]]])]);

        self::assertFalse(Narrowing::isAllowOnly($policy));
    }

    /**
     * Revoking a role narrows when no policy attached to it or to any of its
     * ancestors denies anything, in any scope; an allow-only policy attached to
     * it keeps it narrowing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingARoleNarrowsUnlessADenyIsAttachedToItOrAnAncestor(): void
    {
        $parent = Role::create(['name' => 'staff']);
        $role   = Role::create(['name' => 'editor', 'parent_id' => $parent->id]);
        $other  = Role::create(['name' => 'author']);
        $grants = GrantService::instance();

        self::assertNotNull($grants);
        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $role));

        $grants->attachPolicy($role, self::policy('allowing', 'allow'));
        $grants->attachPolicy(StubIdentity::create(['id' => 'user-1']), self::policy('elsewhere', 'deny'));

        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $role));

        $grants->attachPolicy($parent, self::policy('denying', 'deny'));

        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $role));
        self::assertFalse(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $parent));
        self::assertTrue(Narrowing::isNarrowing(PackagePermissions::ROLE_REVOKE, $other));
    }

    /**
     * Create a policy of one statement with the effect.
     *
     * @param  string  $name
     * @param  string  $effect
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, string $effect): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => $effect, 'actions' => ['posts:*']]]]]);
    }
}
