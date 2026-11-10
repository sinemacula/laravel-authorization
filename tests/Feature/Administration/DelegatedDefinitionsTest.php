<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\AffectedHolders;
use SineMacula\Laravel\Authorization\Administration\DefinitionConstraints;
use SineMacula\Laravel\Authorization\Administration\Impact;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Administration\PolicyRewrite;
use SineMacula\Laravel\Authorization\Administration\PolicyRoute;
use SineMacula\Laravel\Authorization\Administration\RoleAuthority;
use SineMacula\Laravel\Authorization\Administration\RoleParent;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions as Actions;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\AssertsDelegatedRefusals;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for delegated changes to roles, policies and definitions (BL-65
 * part 3, AUTHZ-11.1, D20, N77, N78): role grants judged on the role's whole
 * authority, the policy route and `policy.grantable` bound to a digest, the
 * owner rule, the impact check over every holder and its limit, policy
 * rewrites, boundaries and resource-policy attachments, each decided by a
 * screen exactly as the service decides it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DefinitionConstraints::class)]
#[CoversClass(RoleAuthority::class)]
#[CoversClass(PolicyRoute::class)]
#[CoversClass(PolicyRewrite::class)]
#[CoversClass(RoleParent::class)]
#[CoversClass(Impact::class)]
#[CoversClass(AffectedHolders::class)]
final class DelegatedDefinitionsTest extends TestCase
{
    use ActsAsTenant, AssertsDelegatedRefusals;

    /**
     * A role grant hands out the role's whole authority: every permission it
     * and its ancestors carry must pass the permission route, so one inherited
     * from an ancestor the actor cannot hand out blocks it; with the hierarchy
     * disabled, the ancestor's no longer counts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleGrantNeedsEveryPermissionItsChainCarries(): void
    {
        $actor  = self::actor('admin', [Actions::ROLE_GRANT, 'posts:read']);
        $user   = self::user('user');
        $parent = self::role('parent');
        $child  = self::role('child', $parent);

        self::roles()->grantPermission($parent, self::permission('posts:delete'));
        self::roles()->grantPermission($child, self::permission('posts:read'));

        $grant = static fn (Role $role): \Closure => static fn (): mixed => self::grants()->grantRole($user, $role, actor: $actor);

        self::assertDecided(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, self::roleGrant($user, $child), $grant($child));

        config(['authorization.hierarchy.enabled' => false]);

        self::assertDecided(null, $actor, self::roleGrant($user, $child), $grant($child));
        self::assertTrue($user->fresh()?->hasRole('child'));
    }

    /**
     * An allow a resource policy hands to a role, by naming it or an ancestor
     * as a principal, reaches whoever holds the role later: attaching it to a
     * role no one holds reaches no one, but granting the role, or a role below
     * it, or making it the parent of a held role, hands the allow out, so the
     * actor must be able to hand out what it allows, or be allowed
     * `policy.grantable` on its document, whichever key the role was given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourcePolicyNamingARoleReachesItsLaterHolders(): void
    {
        $actor   = self::actor('admin', [Actions::RESOURCE_POLICY_ATTACH, Actions::ROLE_GRANT, Actions::ROLE_PARENT_SET, 'posts:read']);
        $junior  = self::user('junior');
        $role    = self::roles()->create('deleters', id: '01a1b0c0-0000-7000-8000-0000000000aa');
        $below   = self::role('below', $role);
        $held    = self::role('held');
        $policy  = self::policy('deleting', [['effect' => 'allow', 'actions' => ['posts:delete'], 'principals' => ['role:' . $role->id]]]);
        $grant   = static fn (Role $granted): \Closure => static fn (): mixed => self::grants()->grantRole($junior, $granted, actor: $actor);
        $parent  = static fn (): \Closure => static fn (): mixed => self::roles()->setParent($held->fresh() ?? $held, $role, $actor);
        $screen  = OperationResource::definition(Actions::ROLE_PARENT_SET, $held, ['parent' => $role->id]);
        $attach  = OperationResource::grant(Actions::RESOURCE_POLICY_ATTACH, new Reference('posts', '*'), $policy, GrantScope::platform());
        $refused = DecisionReason::ADMINISTRATION_NOT_GRANTABLE;

        self::grants()->grantRole(self::user('holder'), $held);
        self::assertDecided(null, $actor, $attach, static fn (): mixed => self::resourcePolicies()->attach($policy, 'posts', actor: $actor));
        self::assertDecided($refused, $actor, self::roleGrant($junior, $role), $grant($role));
        self::assertDecided($refused, $actor, self::roleGrant($junior, $below), $grant($below));
        self::assertDecided($refused, $actor, $screen, $parent());
        self::assertFalse(Authorization::for($junior)->check('posts:delete', new Reference('posts', '7'))->isAllowed());

        self::allowGrantable($actor, self::digestOf($policy));

        self::assertDecided(null, $actor, self::roleGrant($junior, $below), $grant($below));
        self::assertDecided(null, $actor, $screen, $parent());
    }

    /**
     * An allow a resource policy hands to a role is contained when the actor
     * holds what it allows, whatever principals it names.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourcePolicyAllowTheActorHoldsIsContained(): void
    {
        $actor  = self::actor('admin', [Actions::ROLE_GRANT, 'posts:read']);
        $junior = self::user('junior');
        $role   = self::role('readers');
        $policy = self::policy('reading', [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['role:' . $role->id, 'user:1']]]);

        self::resourcePolicies()->attach($policy, ['posts', 7]);

        self::assertDecided(null, $actor, self::roleGrant($junior, $role), static fn (): mixed => self::grants()->grantRole($junior, $role, actor: $actor));
    }

    /**
     * A screen that builds a rewrite through `OperationResource::rewrite()`
     * offers policies the digest of the document as it would be stored, so a
     * right conditioned on `resource.change.digest` decides the screen and the
     * policy service alike.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARewriteIsDecidedOnItsDigestByTheScreenAsByTheService(): void
    {
        $actor    = self::actor('admin', []);
        $policy   = self::policy('support', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $approved = ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']], ['effect' => 'deny', 'actions' => ['posts:delete']]]];
        $other    = ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']], ['effect' => 'deny', 'actions' => ['posts:edit']]]];
        $digest   = DocumentDigest::of(PolicyDocument::named($approved, 'support'))->digest;
        $rewrite  = static fn (array $document): \Closure => static fn (): mixed => self::policies()->rewrite($policy->fresh() ?? $policy, $document, $actor);

        self::assertInstanceOf(Model::class, $actor->subject->subject);

        self::grants()->attachPolicy($actor->subject->subject, self::policy('approver', [[
            'effect'     => 'allow',
            'actions'    => [Actions::POLICY_UPDATE],
            'resources'  => [OperationResource::TYPE . ':*'],
            'conditions' => ['eq' => ['resource.change.digest' => $digest]],
        ]]));

        self::assertDecided(DecisionReason::CONDITION_FAILED, $actor, OperationResource::rewrite($policy, $other), $rewrite($other));
        self::assertDecided(null, $actor, OperationResource::rewrite($policy, $approved), $rewrite($approved));
    }

    /**
     * A policy attached to a role's ancestor is handed out with the role: one
     * whose allows cannot be proved contained blocks the grant, until the actor
     * is allowed `policy.grantable` on that policy's document; a role's denies
     * hand out nothing, so never stand in the way.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInheritedPolicyTheActorCannotHandOutBlocksTheGrant(): void
    {
        $actor  = self::actor('admin', [Actions::ROLE_GRANT]);
        $user   = self::user('user');
        $parent = self::role('parent');
        $child  = self::role('child', $parent);
        $scoped = self::policy('scoped', [['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['posts:1']]]);

        self::grants()->attachPolicy($child, self::policy('denying', [['effect' => 'deny', 'actions' => ['posts:*']]]));
        self::grants()->attachPolicy($parent, $scoped);

        $grant = static fn (): mixed => self::grants()->grantRole($user, $child, actor: $actor);

        self::assertDecided(DecisionReason::ADMINISTRATION_UNPROVABLE, $actor, self::roleGrant($user, $child), $grant);

        self::allowGrantable($actor, self::digestOf($scoped));

        self::assertDecided(null, $actor, self::roleGrant($user, $child), $grant);
    }

    /**
     * `policy.grantable` is bound to the policy's document by its digest: a
     * right allowed for one document allows attaching the policy, and once the
     * policy is rewritten it allows nothing until a right names the new
     * document.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPolicyGrantableIsBoundToTheDigest(): void
    {
        $actor  = self::actor('admin', [Actions::POLICY_ATTACH]);
        $first  = self::user('first');
        $second = self::user('second');
        $scoped = self::policy('scoped', [['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['posts:1']]]);
        $attach = static fn (StubIdentity $user): \Closure => static fn (): mixed => self::grants()->attachPolicy($user, $scoped->fresh() ?? $scoped, actor: $actor);
        $screen = static fn (StubIdentity $user): OperationResource => OperationResource::grant(Actions::POLICY_ATTACH, $user, $scoped->fresh() ?? $scoped, GrantScope::platform());

        self::allowGrantable($actor, self::digestOf($scoped));
        self::assertDecided(null, $actor, $screen($first), $attach($first));

        self::policies()->rewrite($scoped, ['statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['posts:2']]]]);

        self::assertDecided(DecisionReason::ADMINISTRATION_UNPROVABLE, $actor, $screen($second), $attach($second));

        self::allowGrantable($actor, self::digestOf($scoped), 'rewritten');

        self::assertDecided(null, $actor, $screen($second), $attach($second));
    }

    /**
     * Only the owner edits (D20): a role a parent tenant owns is edited from
     * that tenant alone, never from a tenant below it, another tenant or the
     * platform, whatever authority the actor holds, and a platform role from
     * the platform alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADefinitionIsEditedOnlyFromItsOwner(): void
    {
        [$parent, $child] = $this->tree();

        $other    = self::createTenant('other');
        $owned    = Role::query()->withoutGlobalScopes()->create(['name' => 'owned', ...self::ownedBy($parent)]);
        $platform = self::role('platform');
        $actor    = self::actor('admin', [Actions::ROLE_UPDATE]);
        $describe = static fn (Role $role): \Closure => static fn (): mixed => self::roles()->describe($role, 'Edits', $actor);
        $screen   = static fn (Role $role): OperationResource => OperationResource::definition(Actions::ROLE_UPDATE, $role, ['description' => 'Edits']);

        foreach ([$child, $other] as $tenant) {
            self::inTenant($tenant, static fn (): mixed => self::assertDecided(DecisionReason::ADMINISTRATION_OWNER, $actor, $screen($owned), $describe($owned)));
            self::inTenant($tenant, static fn (): mixed => self::assertDecided(DecisionReason::ADMINISTRATION_OWNER, $actor, $screen($platform), $describe($platform)));
        }

        self::assertDecided(DecisionReason::ADMINISTRATION_OWNER, $actor, $screen($owned), $describe($owned));
        self::inTenant($parent, static fn (): mixed => self::assertDecided(null, $actor, $screen($owned), $describe($owned)));
        self::assertDecided(null, $actor, $screen($platform), $describe($platform));
    }

    /**
     * A definition is created owned by the tenant the call names, and decided
     * by the owner rule against it: an administrator creates its own tenant's
     * roles, permissions and policies from that tenant's context, never from
     * the platform's or another tenant's, and the platform's from the platform
     * alone; a screen building the same new record gets the same decision.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADefinitionIsCreatedFromItsOwnersContext(): void
    {
        $tenant = self::createTenant('acme');
        $other  = self::createTenant('other');
        $actor  = self::actor('admin', [Actions::ROLE_CREATE, Actions::PERMISSION_CREATE, Actions::POLICY_CREATE]);
        $owned  = self::ownedBy($tenant);
        $policy = ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]];
        $cases  = [
            'a role' => [
                static fn (string $name): OperationResource => OperationResource::definition(Actions::ROLE_CREATE, new Role($owned), ['name' => $name]),
                static fn (string $name): \Closure => static fn (): mixed => self::roles()->create($name, actor: $actor, tenant: $tenant),
            ],
            'a permission' => [
                static fn (string $name): OperationResource => OperationResource::definition(Actions::PERMISSION_CREATE, new Permission($owned), ['name' => 'posts:' . $name]),
                static fn (string $name): \Closure => static fn (): mixed => self::permissions()->create('posts:' . $name, actor: $actor, tenant: $tenant),
            ],
            'a policy' => [
                static fn (string $name): OperationResource => OperationResource::rewrite(new Policy($owned), $policy, ['name' => $name], Actions::POLICY_CREATE),
                static fn (string $name): \Closure => static fn (): mixed => self::policies()->create($name, $policy, actor: $actor, tenant: $tenant),
            ],
        ];

        foreach ($cases as [$screen, $create]) {
            self::assertDecided(DecisionReason::ADMINISTRATION_OWNER, $actor, $screen('platform'), $create('platform'));
            self::inTenant($other, static fn (): mixed => self::assertDecided(DecisionReason::ADMINISTRATION_OWNER, $actor, $screen('other'), $create('other')));
            self::inTenant($tenant, static fn (): mixed => self::assertDecided(null, $actor, $screen('owned'), $create('owned')));
        }

        self::assertSame($tenant->getKey(), Role::query()->withoutGlobalScopes()->where('name', 'owned')->sole()->tenant_id);
        self::assertSame($tenant->getKey(), Permission::query()->withoutGlobalScopes()->where('name', 'posts:owned')->sole()->tenant_id);
        self::assertSame($tenant->getKey(), Policy::query()->withoutGlobalScopes()->where('name', 'owned')->sole()->tenant_id);
        $platform = static fn (string $name): OperationResource => OperationResource::definition(Actions::ROLE_CREATE, new Role, ['name' => $name]);
        $shared   = static fn (string $name): \Closure => static fn (): mixed => self::roles()->create($name, actor: $actor);

        self::assertDecided(null, $actor, $platform('shared'), $shared('shared'));
        self::inTenant($tenant, static fn (): mixed => self::assertDecided(DecisionReason::ADMINISTRATION_OWNER, $actor, $platform('stray'), $shared('stray')));
    }

    /**
     * A role is created only junior to the actor: one ranked equal to or more
     * senior than the actor's rank is refused, and a junior or unranked one is
     * created.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreatingARoleMoreSeniorThanTheActorIsRefused(): void
    {
        $actor  = self::actor('admin', [Actions::ROLE_CREATE], 2);
        $create = static fn (string $name, ?int $rank): \Closure => static fn (): mixed => self::roles()->create($name, rank: $rank, actor: $actor);
        $screen = static fn (?int $rank): OperationResource => OperationResource::definition(Actions::ROLE_CREATE, new Role, ['rank' => $rank]);

        self::assertDecided(DecisionReason::ADMINISTRATION_RANK, $actor, $screen(1), $create('senior', 1));
        self::assertDecided(DecisionReason::ADMINISTRATION_RANK, $actor, $screen(2), $create('peer', 2));
        self::assertDecided(null, $actor, $screen(3), $create('junior', 3));
        self::assertDecided(null, $actor, $screen(null), $create('unranked', null));
        self::assertSame(['junior', 'unranked'], Role::query()->whereIn('name', ['senior', 'peer', 'junior', 'unranked'])->orderBy('name')->pluck('name')->all());
    }

    /**
     * Renaming a permission re-grants it to every holder under its new name:
     * one held by a peer of the actor is refused by rank, one renamed to a
     * wildcard the actor cannot hand out as not grantable, and one renamed
     * within what the actor holds, or held by no one, is made.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARenameThatWidensIsRefusedUnlessEveryHolderPasses(): void
    {
        $actor  = self::actor('admin', [Actions::PERMISSION_RENAME, 'posts:*']);
        $read   = self::permission('posts:read');
        $peer   = self::user('peer', 1);
        $rename = static fn (string $name): \Closure => static fn (): mixed => self::permissions()->rename($read, $name, $actor);
        $screen = static fn (string $name): OperationResource => OperationResource::definition(Actions::PERMISSION_RENAME, $read, ['name' => $name]);

        self::grants()->grantPermission(self::user('user'), $read);
        self::grants()->grantPermission($peer, $read);

        self::assertDecided(DecisionReason::ADMINISTRATION_RANK, $actor, $screen('*'), $rename('*'));

        self::grants()->revokePermission($peer, $read);

        self::assertDecided(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, $screen('*'), $rename('*'));
        self::assertDecided(null, $actor, $screen('posts:view'), $rename('posts:view'));

        $orphan = self::permission('comments:read');

        $renameOrphan = static fn (): mixed => self::permissions()->rename($orphan, '*', $actor);

        self::assertDecided(null, $actor, OperationResource::definition(Actions::PERMISSION_RENAME, $orphan, ['name' => '*']), $renameOrphan);
    }

    /**
     * Adding a permission to a role reaches every holder of the role and of the
     * roles below it: it is refused when one is senior to the actor, when the
     * actor's authority does not reach below the role's tenant, or when the
     * actor holds the role itself, unless also allowed `administration.self`;
     * it is made when every holder is a junior the actor administers.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAddingAPermissionToARoleIsRefusedForASeniorAnOutOfScopeHolderOrTheActor(): void
    {
        $tenant = self::createTenant('tenant');
        $actor  = self::actor('admin', [Actions::PERMISSION_GRANT, 'posts:*']);
        $role   = self::role('editor');
        $below  = self::role('junior-editor', $role);
        $edit   = self::permission('posts:edit');
        $add    = static fn (Role $role, ActingContext $actor): \Closure => static fn (): mixed => self::roles()->grantPermission($role, $edit, actor: $actor);
        $screen = static fn (Role $role): OperationResource => OperationResource::grant(Actions::PERMISSION_GRANT, $role, $edit, new GrantScope(Reference::tenantOf($role)));
        $senior = self::user('senior', 0);

        self::grants()->grantRole(self::user('user'), $role);
        self::grants()->grantRole($senior, $below);

        self::assertDecided(DecisionReason::ADMINISTRATION_RANK, $actor, $screen($role), $add($role, $actor));

        self::grants()->revokeRole($senior, $below);
        self::grants()->grantRole(StubIdentity::query()->findOrFail('admin'), $below);

        self::assertDecided(DecisionReason::ADMINISTRATION_SELF, $actor, $screen($role), $add($role, $actor));

        self::grantAll(StubIdentity::query()->findOrFail('admin'), [Actions::ADMINISTRATION_SELF]);

        self::assertDecided(null, $actor, $screen($role), $add($role, $actor));

        $owned = Role::query()->withoutGlobalScopes()->create(['name' => 'owned', ...self::ownedBy($tenant)]);
        $node  = self::actor('node', [], 1);

        self::grants()->grantPermission(StubIdentity::query()->findOrFail('node'), self::permission(Actions::PERMISSION_GRANT), tenant: $tenant, includeSubtree: false);
        self::grants()->grantRole(self::user('local'), $owned, tenant: $tenant);

        self::inTenant($tenant, static fn (): mixed => self::assertDecided(DecisionReason::ADMINISTRATION_SCOPE, $node, $screen($owned), $add($owned, $node)));
    }

    /**
     * Attaching a policy to a role hands its allows to every holder, so it
     * needs the policy route as well as the impact check; detaching one only
     * narrows unless it denies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttachingAPolicyToARoleNeedsThePolicyRoute(): void
    {
        $actor   = self::actor('admin', [Actions::POLICY_ATTACH, Actions::POLICY_DETACH, 'posts:read']);
        $role    = self::role('editor');
        $reader  = self::policy('reader', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $editor  = self::policy('editor', [['effect' => 'allow', 'actions' => ['posts:edit']]]);
        $denying = self::policy('denying', [['effect' => 'deny', 'actions' => ['posts:read']]]);
        $attach  = static fn (Policy $policy): \Closure => static fn (): mixed => self::grants()->attachPolicy($role, $policy, actor: $actor);
        $screen  = static fn (Policy $policy): OperationResource => OperationResource::grant(Actions::POLICY_ATTACH, $role, $policy, GrantScope::platform());

        self::grants()->grantRole(self::user('user'), $role);
        self::grants()->attachPolicy($role, $denying);

        self::assertDecided(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, $screen($editor), $attach($editor));
        self::assertDecided(null, $actor, $screen($reader), $attach($reader));
        self::assertSame(1, self::grants()->detachPolicy($role, $reader, $actor));
        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_UNPROVABLE, static fn (): int => self::grants()->detachPolicy($role, $denying, $actor));
    }

    /**
     * Setting a parent hands the parent's whole authority, its ancestors'
     * included, to every holder of the role: one the actor cannot hand out is
     * refused, and one it can is made; clearing or replacing a parent whose
     * chain denies anything lifts the deny, so it is unprovable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSettingAParentHandsOutItsWholeAuthority(): void
    {
        $actor   = self::actor('admin', [Actions::ROLE_PARENT_SET, 'posts:read']);
        $role    = self::role('editor');
        $root    = self::role('root');
        $parent  = self::role('parent', $root);
        $reader  = self::role('reader');
        $guarded = self::role('guarded');
        $set     = static fn (?Role $parent): \Closure => static fn (): mixed => self::roles()->setParent($role->fresh() ?? $role, $parent, $actor);
        $screen  = static fn (?Role $parent): OperationResource => OperationResource::definition(Actions::ROLE_PARENT_SET, $role->fresh() ?? $role, ['parent' => $parent?->id]);

        self::roles()->grantPermission($root, self::permission('posts:delete'));
        self::roles()->grantPermission($reader, self::permission('posts:read'));
        self::grants()->attachPolicy($guarded, self::policy('denying', [['effect' => 'deny', 'actions' => ['posts:edit']]]));
        self::grants()->grantRole(self::user('user'), $role);

        self::assertDecided(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, $screen($parent), $set($parent));
        self::assertDecided(null, $actor, $screen($reader), $set($reader));
        self::assertDecided(null, $actor, $screen(null), $set(null));
        self::assertDecided(null, $actor, $screen($guarded), $set($guarded));
        self::assertDecided(DecisionReason::ADMINISTRATION_UNPROVABLE, $actor, $screen(null), $set(null));
        self::assertDecided(DecisionReason::ADMINISTRATION_UNPROVABLE, $actor, $screen($reader), $set($reader));
    }

    /**
     * A rewrite that only narrows a policy passes; one that adds allows needs
     * the impact check over every holder and the route for what it adds; one
     * that lifts a deny is unprovable; and one that widens a policy in use as a
     * boundary needs `administration.unbounded` too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNarrowingRewritesPassAndWideningOnesNeedTheImpactCheckAndTheRoute(): void
    {
        $actor   = self::actor('admin', [Actions::POLICY_UPDATE, 'posts:read', 'posts:edit']);
        $policy  = self::policy('editor', [['effect' => 'allow', 'actions' => ['posts:read']], ['effect' => 'allow', 'actions' => ['posts:edit']]]);
        $user    = self::user('user');
        $read    = ['effect' => 'allow', 'actions' => ['posts:read']];
        $edit    = ['effect' => 'allow', 'actions' => ['posts:edit']];
        $delete  = ['effect' => 'allow', 'actions' => ['posts:delete']];
        $deny    = ['effect' => 'deny', 'actions' => ['posts:archive']];
        $rewrite = static fn (array $statements): \Closure => static fn (): mixed => self::policies()->rewrite($policy->fresh() ?? $policy, ['statements' => $statements], $actor);

        self::grants()->attachPolicy($user, $policy);

        self::assertDecided(null, $actor, self::rewriteOf($policy, [$read]), $rewrite([$read]));
        self::assertDecided(null, $actor, self::rewriteOf($policy, [$read, $deny]), $rewrite([$read, $deny]));
        self::assertDecided(null, $actor, self::rewriteOf($policy, [$read, $edit, $deny]), $rewrite([$read, $edit, $deny]));
        $widened = [$read, $edit, $delete, $deny];

        self::assertDecided(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, self::rewriteOf($policy, $widened), $rewrite($widened));
        self::assertDecided(DecisionReason::ADMINISTRATION_UNPROVABLE, $actor, self::rewriteOf($policy, [$read, $edit]), $rewrite([$read, $edit]));

        self::grantAll(StubIdentity::query()->findOrFail('admin'), ['posts:delete']);
        self::grants()->grantRole($user, self::role('senior', rank: 0));

        self::assertDecided(DecisionReason::ADMINISTRATION_RANK, $actor, self::rewriteOf($policy, $widened), $rewrite($widened));

        self::grants()->revokeRole($user, 'senior');
        self::boundaries()->set(self::user('bounded'), $policy->fresh() ?? $policy);

        self::assertDecided(DecisionReason::ADMINISTRATION_UNPROVABLE, $actor, self::rewriteOf($policy, $widened), $rewrite($widened));

        self::grantAll(StubIdentity::query()->findOrFail('admin'), [Actions::ADMINISTRATION_UNBOUNDED]);

        self::assertDecided(null, $actor, self::rewriteOf($policy, $widened), $rewrite($widened));
    }

    /**
     * The impact check reads at most `authorization.administration.max_impact`
     * holders: a change reaching more is refused as unprovable, never
     * approximated, and one reaching no more is made.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGoingOverTheImpactLimitRefuses(): void
    {
        config(['authorization.administration.max_impact' => 2]);

        $actor  = self::actor('admin', [Actions::PERMISSION_GRANT, 'posts:*']);
        $role   = self::role('editor');
        $edit   = self::permission('posts:edit');
        $add    = static fn (): mixed => self::roles()->grantPermission($role, $edit, actor: $actor);
        $screen = OperationResource::grant(Actions::PERMISSION_GRANT, $role, $edit, GrantScope::platform());

        foreach (['one', 'two', 'three'] as $id) {
            self::grants()->grantRole(self::user($id), $role);
        }

        self::assertDecided(DecisionReason::ADMINISTRATION_UNPROVABLE, $actor, $screen, $add);

        self::grants()->revokeRole(self::user('three'), $role);

        self::assertDecided(null, $actor, $screen, $add);
    }

    /**
     * A delegated boundary that only adds or tightens a cap is set on its
     * action and the grantee rules; replacing it with a wider one, or removing
     * it, needs `administration.unbounded`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundaryNarrowsOrNeedsTheUnboundedRight(): void
    {
        $actor  = self::actor('admin', [Actions::BOUNDARY_SET, Actions::BOUNDARY_REMOVE]);
        $user   = self::user('user');
        $wide   = self::policy('wide', [['effect' => 'allow', 'actions' => ['posts:*']]]);
        $narrow = self::policy('narrow', [['effect' => 'allow', 'actions' => ['posts:*']], ['effect' => 'deny', 'actions' => ['posts:delete']]]);
        $set    = static fn (Policy $policy): \Closure => static fn (): mixed => self::boundaries()->set($user, $policy, actor: $actor);
        $screen = static fn (Policy $policy): OperationResource => OperationResource::grant(Actions::BOUNDARY_SET, $user, $policy, GrantScope::platform());

        self::assertDecided(null, $actor, $screen($wide), $set($wide));
        self::assertDecided(null, $actor, $screen($narrow), $set($narrow));
        self::assertDecided(DecisionReason::ADMINISTRATION_UNPROVABLE, $actor, $screen($wide), $set($wide));
        self::assertDecided(
            DecisionReason::ADMINISTRATION_UNPROVABLE,
            $actor,
            OperationResource::revoke(Actions::BOUNDARY_REMOVE, $user, $narrow, GrantScope::platform()),
            static fn (): mixed => self::boundaries()->remove($user, actor: $actor),
        );
    }

    /**
     * A resource policy hands its allows to every principal it names, on one
     * record or on the whole type: each must be a junior the actor administers,
     * the holders of a role a selector names included, and the actor must be
     * able to hand out what the policy allows.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourcePolicyIsWeighedAgainstEveryPrincipalItNames(): void
    {
        $actor  = self::actor('admin', [Actions::RESOURCE_POLICY_ATTACH, 'posts:read']);
        $junior = self::user('junior');
        $senior = self::user('senior', 0);
        $role   = self::role('readers');
        $named  = static fn (string $name, string $action, array $principals): Policy => self::policy($name, [
            ['effect' => 'allow', 'actions' => [$action], 'principals' => $principals],
        ]);
        $attach = static fn (Policy $policy, mixed $resource): \Closure => static fn (): mixed => self::resourcePolicies()->attach($policy, $resource, actor: $actor);
        $screen = static fn (Policy $policy, string $id): OperationResource => OperationResource::grant(
            Actions::RESOURCE_POLICY_ATTACH,
            new Reference('posts', $id),
            $policy,
            GrantScope::platform(),
        );

        $toJunior = $named('to-junior', 'posts:read', [self::selector($junior)]);
        $toSenior = $named('to-senior', 'posts:read', [self::selector($senior)]);
        $toRole   = $named('to-role', 'posts:read', ['role:' . $role->id]);
        $editing  = $named('editing', 'posts:edit', [self::selector($junior)]);

        self::assertDecided(null, $actor, $screen($toJunior, '7'), $attach($toJunior, ['posts', 7]));
        self::assertDecided(null, $actor, $screen($toJunior, '*'), $attach($toJunior, 'posts'));
        self::assertDecided(DecisionReason::ADMINISTRATION_RANK, $actor, $screen($toSenior, '7'), $attach($toSenior, ['posts', 7]));
        self::assertDecided(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, $screen($editing, '*'), $attach($editing, 'posts'));

        self::grants()->grantRole($junior, $role);

        self::assertDecided(null, $actor, $screen($toRole, '*'), $attach($toRole, 'posts'));

        self::grants()->grantRole($senior, $role);

        self::assertDecided(DecisionReason::ADMINISTRATION_RANK, $actor, $screen($toRole, '7'), $attach($toRole, ['posts', 7]));
    }

    /**
     * Assert the screen decides the operation as the call is decided: refused
     * for the reason, the call then writing nothing, or allowed, the call then
     * made.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null  $refusal
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $screen
     * @param  \Closure(): mixed  $call
     * @return null
     *
     * @throws \Throwable
     */
    private static function assertDecided(?DecisionReason $refusal, ActingContext $actor, OperationResource $screen, \Closure $call): null
    {
        $decision = $actor->check($screen);

        if ($refusal !== null) {
            self::assertSame($refusal, $decision->reason, 'The screen decided it as ' . ($decision->reason->value ?? 'allowed'));
            self::assertDelegatedRefusal($refusal, $call);

            return null;
        }

        self::assertTrue($decision->isAllowed(), 'The screen refused it as ' . $decision->reason?->value);

        $call();

        return null;
    }

    /**
     * Return the operation resource of a rewrite of the policy to the
     * statements, as the policy service builds it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    private static function rewriteOf(Policy $policy, array $statements): OperationResource
    {
        return OperationResource::rewrite($policy->fresh() ?? $policy, ['statements' => $statements]);
    }

    /**
     * Return the operation resource of a grant of the role to the user,
     * platform-wide.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    private static function roleGrant(StubIdentity $user, Role $role): OperationResource
    {
        return OperationResource::grant(Actions::ROLE_GRANT, $user, $role, GrantScope::platform());
    }

    /**
     * Allow the actor `policy.grantable` on any operation whose descriptor
     * names the document of the digest, through a policy attached to it.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @param  string  $digest
     * @param  string  $name
     * @return void
     *
     * @throws \Throwable
     */
    private static function allowGrantable(ActingContext $actor, string $digest, string $name = 'grantable'): void
    {
        $statement = [
            'effect'     => 'allow',
            'actions'    => [Actions::POLICY_GRANTABLE],
            'resources'  => [OperationResource::TYPE . ':*'],
            'conditions' => ['eq' => ['resource.digest' => $digest]],
        ];

        self::assertInstanceOf(Model::class, $actor->subject->subject);

        self::grants()->attachPolicy($actor->subject->subject, self::policy($name, [$statement]));
    }

    /**
     * Return the digest of the policy's document as stored.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return string
     *
     * @throws \JsonException
     */
    private static function digestOf(Policy $policy): string
    {
        $document = ($policy->fresh() ?? $policy)->document;

        return DocumentDigest::of($document)->digest;
    }

    /**
     * Run the call from the tenant, or the platform for none.
     *
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @param  \Closure(): mixed  $call
     * @return mixed
     */
    private static function inTenant(?StubTenant $tenant, \Closure $call): mixed
    {
        return TenantScope::within($tenant === null ? null : Reference::of($tenant), null, $call);
    }

    /**
     * Bind a tenant tree of a parent and its child, and return both.
     *
     * @return array{\Tests\Feature\Stubs\StubTenant, \Tests\Feature\Stubs\StubTenant}
     */
    private function tree(): array
    {
        [$parent, $child] = \array_map(self::createTenant(...), ['parent', 'child']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($parent)));

        return [$parent, $child];
    }

    /**
     * Return the acting context of a new identity granted each permission
     * platform-wide, and a platform role of the rank, or none for null.
     *
     * @param  string  $id
     * @param  list<string>  $permissions
     * @param  int|null  $rank
     * @return \SineMacula\Laravel\Authorization\Administration\ActingContext
     *
     * @throws \Throwable
     */
    private static function actor(string $id, array $permissions, ?int $rank = 1): ActingContext
    {
        $actor = self::user($id, $rank);

        self::grantAll($actor, $permissions);

        return ActingContext::for($actor);
    }

    /**
     * Grant each permission to the identity, platform-wide.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  list<string>  $permissions
     * @return void
     *
     * @throws \Throwable
     */
    private static function grantAll(StubIdentity $identity, array $permissions): void
    {
        foreach ($permissions as $permission) {
            self::grants()->grantPermission($identity, self::permission($permission));
        }
    }

    /**
     * Return the identity with the id, created on first use, holding a platform
     * role of the rank, or none for null.
     *
     * @param  string  $id
     * @param  int|null  $rank
     * @return \Tests\Feature\Stubs\StubIdentity
     *
     * @throws \Throwable
     */
    private static function user(string $id, ?int $rank = null): StubIdentity
    {
        $user = StubIdentity::query()->firstOrCreate(['id' => $id]);

        if ($rank !== null) {
            self::grants()->grantRole($user, self::role('rank-' . $rank, rank: $rank));
        }

        return $user;
    }

    /**
     * Return the principal selector naming the identity.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @return string
     */
    private static function selector(StubIdentity $identity): string
    {
        $reference = Reference::of($identity);

        return $reference->type . ':' . $reference->id;
    }

    /**
     * Return the platform role of the name, created on first use with the
     * parent and the rank.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Models\Role|null  $parent
     * @param  int|null  $rank
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function role(string $name, ?Role $parent = null, ?int $rank = null): Role
    {
        return Role::query()->firstOrCreate(['name' => $name], ['parent_id' => $parent?->id, 'rank' => $rank]);
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
     * Create a policy of the statements.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, array $statements): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => $statements]]);
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

    /**
     * Return the role service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\RoleService
     */
    private static function roles(): RoleService
    {
        return app(RoleService::class);
    }

    /**
     * Return the permission service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\PermissionService
     */
    private static function permissions(): PermissionService
    {
        return app(PermissionService::class);
    }

    /**
     * Return the policy service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\PolicyService
     */
    private static function policies(): PolicyService
    {
        return app(PolicyService::class);
    }

    /**
     * Return the boundary service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\BoundaryService
     */
    private static function boundaries(): BoundaryService
    {
        return app(BoundaryService::class);
    }

    /**
     * Return the resource policy service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\ResourcePolicyService
     */
    private static function resourcePolicies(): ResourcePolicyService
    {
        return app(ResourcePolicyService::class);
    }
}
