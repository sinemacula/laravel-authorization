<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\DefinitionConstraints;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions as Actions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `DefinitionConstraints`: the owner rule and the constraints
 * of each change to a shared definition, a role's permissions and policies, and
 * a resource's policies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DefinitionConstraints::class)]
final class DefinitionConstraintsTest extends TestCase
{
    /**
     * A definition, a role's permissions and a role's policies are changed only
     * from the tenant that owns the definition or the role, a platform one from
     * the platform, whether or not the change narrows; a change to a role that
     * is gone has no owner to make it from; a resource policy's attachment is
     * never weighed by the rule.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheOwnersContextChangesADefinition(): void
    {
        $tenant   = new Reference('tenant', 'a');
        $owned    = Role::query()->withoutGlobalScopes()->create(['name' => 'owned', 'tenant_type' => $tenant->type, 'tenant_id' => $tenant->id]);
        $platform = Role::query()->create(['name' => 'platform']);
        $edit     = self::permission('posts:edit');
        $rename   = OperationResource::definition(Actions::ROLE_RENAME, $owned, ['name' => 'renamed']);
        $revoke   = OperationResource::revoke(Actions::PERMISSION_REVOKE, $owned, $edit, new GrantScope($tenant));
        $detach   = OperationResource::revoke(Actions::RESOURCE_POLICY_DETACH, new Reference('posts', '7'), self::policy('reader', 'allow'), GrantScope::platform());
        $missing  = new Reference($owned->getMorphClass(), '01a1b0c0-0000-7000-8000-00000000dead');
        $gone     = OperationResource::revoke(Actions::PERMISSION_REVOKE, $missing, $edit, GrantScope::platform());

        foreach ([$rename, $revoke] as $operation) {
            self::assertSame(DecisionReason::ADMINISTRATION_OWNER, self::refusal($operation, null));
            self::assertSame(DecisionReason::ADMINISTRATION_OWNER, self::refusal($operation, new Reference('tenant', 'b')));
            self::assertSame(DecisionReason::ADMINISTRATION_OWNER, self::refusal($operation, new Reference('team', 'a')));
            self::assertNull(self::refusal($operation, $tenant));
        }

        self::assertSame(DecisionReason::ADMINISTRATION_OWNER, self::refusal(OperationResource::definition(Actions::ROLE_RENAME, $platform, ['name' => 'renamed']), $tenant));
        self::assertNull(self::refusal(OperationResource::definition(Actions::ROLE_RENAME, $platform, ['name' => 'renamed']), null));
        self::assertSame(DecisionReason::ADMINISTRATION_OWNER, self::refusal($gone, null));
        self::assertNull(self::refusal($detach, $tenant));
    }

    /**
     * Creating, describing and deleting a definition widen no one, but a role
     * must be created junior to the actor, a role or a policy a deny reaches is
     * never deleted, and an action no rule covers is unprovable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachChangeToADefinitionIsWeighedByWhatItChanges(): void
    {
        $role    = Role::query()->create(['name' => 'editor']);
        $guarded = Role::query()->create(['name' => 'guarded']);
        $read    = self::permission('posts:read');
        $allow   = self::policy('reader', 'allow');
        $deny    = self::policy('denying', 'deny');

        self::grants()->attachPolicy($guarded, $deny);

        $cases = [
            'creating a junior role'        => [Actions::ROLE_CREATE, new Role, ['rank' => 9], null],
            'creating a senior role'        => [Actions::ROLE_CREATE, new Role, ['rank' => 1], DecisionReason::ADMINISTRATION_RANK],
            'describing a role'             => [Actions::ROLE_UPDATE, $role, ['description' => 'Edits'], null],
            'deleting a role'               => [Actions::ROLE_DELETE, $role, [], null],
            'deleting a guarded role'       => [Actions::ROLE_DELETE, $guarded, [], DecisionReason::ADMINISTRATION_UNPROVABLE],
            'a role action no rule names'   => [Actions::ROLE_GRANT, $role, [], DecisionReason::ADMINISTRATION_UNPROVABLE],
            'creating a permission'         => [Actions::PERMISSION_CREATE, new Permission, ['name' => 'posts:new'], null],
            'describing a permission'       => [Actions::PERMISSION_UPDATE, $read, ['description' => 'Reads'], null],
            'deleting a permission'         => [Actions::PERMISSION_DELETE, $read, [], null],
            'regarding a permission'        => [Actions::PERMISSION_UPDATE, $read, ['guard' => 'api'], null],
            'creating a policy'             => [Actions::POLICY_CREATE, new Policy, ['name' => 'fresh'], null],
            'renaming a policy'             => [Actions::POLICY_RENAME, $allow, ['name' => 'viewer'], null],
            'describing a policy'           => [Actions::POLICY_UPDATE, $allow, ['description' => 'Reads'], null],
            'deleting an allowing policy'   => [Actions::POLICY_DELETE, $allow, [], null],
            'deleting a denying policy'     => [Actions::POLICY_DELETE, $deny, [], DecisionReason::ADMINISTRATION_UNPROVABLE],
            'a policy action no rule names' => [Actions::POLICY_ATTACH, $allow, [], DecisionReason::ADMINISTRATION_UNPROVABLE],
            'an unknown record'             => [Actions::ROLE_UPDATE, StubIdentity::query()->create(['id' => 'record']), [], DecisionReason::ADMINISTRATION_UNPROVABLE],
        ];

        foreach ($cases as $name => [$action, $record, $change, $refusal]) {
            self::assertSame($refusal, self::refusal(OperationResource::definition($action, $record, $change), null), $name);
        }
    }

    /**
     * Changing a role's rank leaves it junior to the actor, and a rank made
     * more senior is weighed against the role's holders, the new rank counting
     * as theirs; a rank made more junior, or cleared, reaches no one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARankMadeMoreSeniorIsWeighedAgainstTheHolders(): void
    {
        $role = Role::query()->create(['name' => 'editor', 'rank' => 8]);

        self::grants()->grantRole(StubIdentity::query()->create(['id' => 'holder']), $role);
        self::grants()->grantRole(StubIdentity::query()->create(['id' => 'senior']), Role::query()->create(['name' => 'senior', 'rank' => 1]));

        $rank = static fn (?int $rank): ?DecisionReason => self::refusal(OperationResource::definition(Actions::ROLE_UPDATE, $role, ['rank' => $rank]), null);

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $rank(2));
        self::assertNull($rank(5));
        self::assertNull($rank(9));
        self::assertNull($rank(null));

        self::grants()->grantRole(StubIdentity::query()->findOrFail('senior'), $role);

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $rank(5));
        self::assertNull($rank(9));
    }

    /**
     * A change to what a role carries reaches its holders, so one with none
     * widens no one; adding a permission or attaching a policy to a role held
     * by a peer is refused by rank; detaching a denying policy from a role,
     * granting a role a role, and attaching anything but a policy to a
     * resource, are unprovable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeToWhatARoleCarriesReachesItsHolders(): void
    {
        $role  = Role::query()->create(['name' => 'editor']);
        $edit  = self::permission('posts:edit');
        $allow = self::policy('reader', 'allow');
        $deny  = self::policy('denying', 'deny');

        $grant  = OperationResource::grant(Actions::PERMISSION_GRANT, $role, $edit, GrantScope::platform());
        $attach = OperationResource::grant(Actions::POLICY_ATTACH, $role, $allow, GrantScope::platform());

        self::assertNull(self::refusal($grant, null));
        self::assertNull(self::refusal($attach, null));

        self::grants()->grantRole(StubIdentity::query()->create(['id' => 'peer']), Role::query()->create(['name' => 'peer', 'rank' => 1]));
        self::grants()->grantRole(StubIdentity::query()->findOrFail('peer'), $role);

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::refusal($grant, null));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::refusal($attach, null));
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::refusal(OperationResource::revoke(Actions::POLICY_DETACH, $role, $deny, GrantScope::platform()), null));
        $other = Role::query()->create(['name' => 'other']);
        $posts = new Reference('posts', '7');

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::refusal(OperationResource::grant(Actions::ROLE_GRANT, $role, $other, GrantScope::platform()), null));
        $notAPolicy = OperationResource::grant(Actions::RESOURCE_POLICY_ATTACH, $posts, $edit, GrantScope::platform());

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::refusal($notAPolicy, null));
        self::assertNull(self::refusal(OperationResource::grant(Actions::RESOURCE_POLICY_ATTACH, new Reference('posts', '7'), $allow, GrantScope::platform()), null));
    }

    /**
     * Return why the operation is refused when its action is allowed, the actor
     * ranked 2, every further check allowed and the grantable rights held, made
     * from the tenant given.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $from
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     *
     * @throws \Throwable
     */
    private static function refusal(OperationResource $operation, ?Reference $from): ?DecisionReason
    {
        $actor = StubIdentity::query()->firstOrCreate(['id' => 'admin']);

        if (!$actor->hasRole('chief')) {
            self::grants()->grantRole($actor, Role::query()->create(['name' => 'chief', 'rank' => 2]));
            self::grants()->grantPermission($actor, self::permission('authorization:*'));
        }

        $checks = new FurtherChecks(new Subject($actor, $actor), static fn (): Decision => Decision::allow(DecisionStage::ALLOW), static fn (): null => null, $from);

        return DefinitionConstraints::refusal($operation, $operation->toResourceReference(), $checks);
    }

    /**
     * Return the platform permission of the name, created on first use.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private static function permission(string $name): Permission
    {
        return Permission::query()->firstOrCreate(['name' => $name]);
    }

    /**
     * Return the policy of the name, one statement of the effect on every post
     * action, created on first use.
     *
     * @param  string  $name
     * @param  string  $effect
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, string $effect): Policy
    {
        $statement = ['effect' => $effect, 'actions' => ['posts:*']];

        return Policy::query()->where('name', $name)->first() ?? Policy::create(['name' => $name, 'document' => ['statements' => [$statement]]]);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        return app(GrantService::class);
    }
}
