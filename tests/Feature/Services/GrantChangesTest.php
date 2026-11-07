<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\Support\GrantChanges;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\ApiGuardedUser;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `GrantChanges`, which reads the grant tables for the grant
 * service and names the changes a sync or the revocation of everything makes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantChanges::class)]
final class GrantChangesTest extends TestCase
{
    use ActsAsTenant;

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A sync's changes are a grant of each kept row the grantee does not hold
     * live in the scope, a new one or an expired one, and a revocation of each
     * dropped row with the reach it had; a row held live decides nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASyncsChangesAreItsGrantsAndRevocations(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $live    = Role::create(['name' => 'live']);
        $expired = Role::create(['name' => 'expired']);
        $fresh   = Role::create(['name' => 'fresh']);
        $dropped = Role::create(['name' => 'dropped']);

        self::grants()->grantRole($user, $live);
        self::grants()->grantRole($user, $expired, Carbon::now()->addMinute());
        self::grants()->grantRole($user, $dropped, includeSubtree: false);

        Carbon::setTestNow(Carbon::now()->addHour());

        $reference = Reference::of($user);
        $scope     = GrantScope::platform();
        $table     = GrantChanges::table(GrantTarget::ROLE, $reference, null, $scope);
        $keep      = [$live->id => $live, $expired->id => $expired, $fresh->id => $fresh];
        $changes   = GrantChanges::ofSync(GrantTarget::ROLE, $reference, $table, $keep, [$dropped->id => true], $scope, null);

        self::assertSame(
            [[PackagePermissions::ROLE_GRANT, 'expired', false], [PackagePermissions::ROLE_GRANT, 'fresh', false], [PackagePermissions::ROLE_REVOKE, 'dropped', true]],
            \array_map(static fn (OperationResource $change): array => [$change->action, $change->attributes()['role'] ?? null, $change->isNarrowing], $changes),
        );
        self::assertTrue($changes[2]->attributes()['subtree']);
        self::assertSame([], GrantChanges::ofSync(GrantTarget::ROLE, $reference, $table, [$live->id => $live], [], $scope, null));
    }

    /**
     * Revoking everything changes every role, permission and policy the grantee
     * holds, and every boundary it has, in every scope, each under its own
     * action and in its own scope.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEverythingNamesEveryGrantAndBoundary(): void
    {
        $tenant = self::createTenant('tenant-a');
        $user   = StubIdentity::create(['id' => 'user-1']);
        $cap    = Policy::create(['name' => 'cap', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:*']]]]]);

        self::grants()->grantRole($user, Role::create(['name' => 'editor']), tenant: $tenant);
        self::grants()->grantPermission($user, Permission::create(['name' => 'posts:edit']));
        self::grants()->attachPolicy($user, Policy::create(['name' => 'audit', 'document' => ['statements' => []]]));
        BoundaryService::instance()?->set($user, $cap, $tenant);
        self::grants()->grantRole(StubIdentity::create(['id' => 'user-2']), Role::create(['name' => 'other']));

        $changes = GrantChanges::everything(Reference::of($user));

        self::assertSame(
            [PackagePermissions::ROLE_REVOKE, PackagePermissions::PERMISSION_REVOKE, PackagePermissions::POLICY_DETACH, PackagePermissions::BOUNDARY_REMOVE],
            \array_map(static fn (OperationResource $change): string => $change->action, $changes),
        );
        self::assertEquals(Reference::of($tenant), $changes[0]->tenant);
        self::assertNull($changes[1]->tenant);
        self::assertEquals(Reference::of($tenant), $changes[3]->tenant);
        self::assertSame('cap', $changes[3]->attributes()['policy']);
        self::assertSame([], GrantChanges::everything(new Reference('user', 'nobody')));
    }

    /**
     * The writer of a grantee's rows records the actor given on each row it
     * writes, in the scope.
     *
     * @return void
     */
    public function testTheTableWritesInTheScopeForTheActor(): void
    {
        $role  = Role::create(['name' => 'editor']);
        $table = GrantChanges::table(GrantTarget::ROLE, new Reference('user', '1'), new Reference('admin', '9'), new GrantScope(null, 'admin', true));

        $table->grant($role->id, null);

        self::assertSame([$role->id], $table->held());
        self::assertSame([$role->id], $table->live([$role->id]));
        self::assertSame(['admin', '9'], \array_values((array) DB::table('authorizable_roles')->sole(['granted_by_type', 'granted_by_id'])));
        self::assertSame([], GrantChanges::table(GrantTarget::ROLE, new Reference('user', '1'), null, GrantScope::platform())->held());
    }

    /**
     * A model's key is read as a string, and a grantee's guard through its
     * optional hook, none without one.
     *
     * @return void
     */
    public function testReadsKeysAndGuards(): void
    {
        $role = Role::create(['name' => 'editor']);

        self::assertSame($role->id, GrantChanges::key($role));
        self::assertSame('api', GrantChanges::guard(new ApiGuardedUser));
        self::assertNull(GrantChanges::guard(new Reference('user', '1')));
        self::assertNull(GrantChanges::guard(StubIdentity::create(['id' => 'user-1'])));
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        $service = GrantService::instance();

        self::assertNotNull($service);

        return $service;
    }
}
