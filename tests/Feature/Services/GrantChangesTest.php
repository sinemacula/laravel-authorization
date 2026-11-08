<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Events\Identity\BoundaryRemoved;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\Support\GrantChanges;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\ApiGuardedUser;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\VanishedPolicy;
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
     * live in the scope, a new one or an expired one, the row kept unchanged
     * for each it holds live, and a revocation of each dropped row with the
     * reach it had; a sync that changes nothing decides its revocation
     * unchanged.
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
        $live      = $table->live(\array_map(\strval(...), \array_keys($keep)));
        $changes   = GrantChanges::ofSync(GrantTarget::ROLE, $reference, $live, $keep, [$dropped->id => false], $scope, null);

        self::assertSame([
            [PackagePermissions::ROLE_GRANT, 'live', true, true],
            [PackagePermissions::ROLE_GRANT, 'expired', false, null],
            [PackagePermissions::ROLE_GRANT, 'fresh', false, null],
            [PackagePermissions::ROLE_REVOKE, 'dropped', true, null],
        ], \array_map(self::summary(...), $changes));
        self::assertFalse($changes[3]->attributes()['subtree']);

        $none = GrantChanges::ofSync(GrantTarget::ROLE, $reference, [], [], [], $scope, null);

        self::assertSame([[PackagePermissions::ROLE_REVOKE, null, true, true]], \array_map(self::summary(...), $none));
        self::assertSame([$reference->type, 'user-1'], [$none[0]->attributes()['grantee_type'], $none[0]->attributes()['grantee_id']]);
    }

    /**
     * A revocation removes the candidates the grantee holds, each with the
     * reach it holds it with; of a name it holds none of, the candidate the
     * lookup ranks first, held by no row, so the revocation asked for is still
     * decided; and a candidate named by model whether or not it is held.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationDecidesWhatIsHeldElseTheFirstCandidate(): void
    {
        $tenant  = self::createTenant('tenant-a');
        $user    = StubIdentity::create(['id' => 'user-1']);
        $first   = Role::create(['name' => 'editor']);
        $second  = Role::create(['name' => 'editor', ...self::ownedBy($tenant)]);
        $grantee = Reference::of($user);
        $named   = new GrantScope(Reference::of($tenant));

        $none = GrantChanges::revocations(GrantTarget::ROLE, $grantee, null, [$first, $second], $named);

        self::assertCount(1, $none);
        self::assertSame([$first->id, null, true], [$none[0][2], $none[0][3], $none[0][4]->includeSubtree]);

        self::grants()->grantRole($user, $second, tenant: $tenant, includeSubtree: false);

        $held = GrantChanges::revocations(GrantTarget::ROLE, $grantee, null, [$first, $second], $named);

        self::assertCount(1, $held);
        self::assertSame([$second->id, false, false], [$held[0][2], $held[0][3], $held[0][4]->includeSubtree]);
        self::assertEquals(Reference::of($tenant), $held[0][4]->tenant);
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
     * Revoking everything as trusted work revokes every row of every kind and
     * every boundary, whoever granted them; revoking what was decided revokes
     * exactly those rows, each by its key in its scope, and the boundaries
     * decided, leaving a row granted since, and a row decided that is gone
     * refuses, revoking nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEverythingIsRevokedOrExactlyWhatWasDecided(): void
    {
        $tenant    = self::createTenant('tenant-a');
        $user      = StubIdentity::create(['id' => 'user-1']);
        $grantee   = Reference::of($user);
        $cap       = Policy::create(['name' => 'cap', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:*']]]]]);
        $operation = Operation::begin();

        self::grants()->grantRole($user, Role::create(['name' => 'editor']), tenant: $tenant);
        self::grants()->grantPermission($user, Permission::create(['name' => 'posts:edit']));
        BoundaryService::instance()?->set($user, $cap, $tenant);

        $decided = GrantChanges::everything($grantee);

        self::grants()->grantPermission($user, Permission::create(['name' => 'posts:read']), tenant: $tenant);

        $events = OperationScope::run($operation, static fn (Operation $operation): array => GrantChanges::revokeDecided($grantee, $operation, $decided));

        self::assertSame([RoleRevoked::class, PermissionRevoked::class, BoundaryRemoved::class], \array_map(\get_class(...), $events));
        self::assertSame(1, DB::table('authorizable_permissions')->where('authorizable_id', 'user-1')->count());
        self::assertSame(0, DB::table('authorizable_boundaries')->count());

        $gone = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $grantee, Permission::create(['name' => 'posts:delete']), GrantScope::platform());

        try {
            $decided = [...GrantChanges::everything($grantee), $gone];

            OperationScope::run($operation, static fn (Operation $operation): array => GrantChanges::revokeDecided($grantee, $operation, $decided));

            self::fail('A row decided that is gone was revoked.');
        } catch (DependencyChangedException $exception) {
            self::assertStringContainsString('[authorizable_permissions]', $exception->getMessage());
        }

        self::assertSame(1, DB::table('authorizable_permissions')->where('authorizable_id', 'user-1')->count());

        BoundaryService::instance()?->set($user, $cap);

        $everything = OperationScope::run($operation, static fn (Operation $operation): array => GrantChanges::revokeEverywhere($grantee, $operation));

        self::assertSame([PermissionRevoked::class, BoundaryRemoved::class], \array_map(\get_class(...), $everything));
        self::assertSame([], GrantChanges::everything($grantee));
    }

    /**
     * The removal of a boundary whose policy cannot be read cannot be named, so
     * revoking everything is refused before anything is decided.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundaryWhosePolicyIsGoneRefusesEverything(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $cap  = Policy::create(['name' => 'cap', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:*']]]]]);

        BoundaryService::instance()?->set($user, $cap);

        config()->set('authorization.models.policy', VanishedPolicy::class);

        $this->expectException(InvalidGrantTargetException::class);

        GrantChanges::everything(Reference::of($user));
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
     * Return the action of the change, the name of its role, whether it only
     * narrows, and whether it changes nothing.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $change
     * @return array{string, mixed, bool, mixed}
     */
    private static function summary(OperationResource $change): array
    {
        $attributes = $change->attributes();

        return [$change->action, $attributes['role'] ?? null, $change->isNarrowing, $attributes['unchanged'] ?? null];
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
