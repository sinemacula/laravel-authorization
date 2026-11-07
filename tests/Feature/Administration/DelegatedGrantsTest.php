<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\HeldLifetime;
use SineMacula\Laravel\Authorization\Administration\OperationConstraints;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Administration\OwnerConstraint;
use SineMacula\Laravel\Authorization\Administration\Possession;
use SineMacula\Laravel\Authorization\Administration\PossessionLimits;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions as Actions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\AssertsDelegatedRefusals;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for delegated direct grants (BL-65 part 2, AUTHZ-11.1,
 * AUTHZ-3.5): rank, self, the administered scope, the owner, possession and
 * explicit grantability, expiry and atomic batches, each decided by a screen
 * exactly as the grant service decides it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(OperationConstraints::class)]
#[CoversClass(Possession::class)]
#[CoversClass(PossessionLimits::class)]
#[CoversClass(HeldLifetime::class)]
#[CoversClass(OwnerConstraint::class)]
final class DelegatedGrantsTest extends TestCase
{
    use ActsAsTenant, AssertsDelegatedRefusals;

    /** @var list<string> The actions a granting administrator holds. */
    private const array GRANTING = [Actions::PERMISSION_GRANT, Actions::PERMISSION_REVOKE];

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
     * The rank table (N76): the actor's rank, the grantee's, and whether rank
     * lets the actor act on it, null when it does.
     *
     * @return iterable<string, array{int|null, int|null, \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null}>
     */
    public static function ranks(): iterable
    {
        yield 'senior on junior' => [1, 5, null];
        yield 'senior on unranked' => [1, null, null];
        yield 'junior on senior' => [5, 1, DecisionReason::ADMINISTRATION_RANK];
        yield 'equal' => [3, 3, DecisionReason::ADMINISTRATION_RANK];
        yield 'unranked on ranked' => [null, 5, DecisionReason::ADMINISTRATION_RANK];
        yield 'unranked on unranked' => [null, null, DecisionReason::ADMINISTRATION_RANK];
    }

    /**
     * Rank weighs every change to a subject alike: a grant, a revocation and a
     * sync, the screen deciding as the service does.
     *
     * @param  int|null  $actorRank
     * @param  int|null  $targetRank
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null  $refusal
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('ranks')]
    public function testRankWeighsGrantsRevocationsAndSyncs(?int $actorRank, ?int $targetRank, ?DecisionReason $refusal): void
    {
        $actor = self::actor('admin', ['authorization:*' => []], $actorRank);
        $user  = self::user('user', $targetRank);

        self::grants()->grantPermission($user, self::permission('posts:read'));

        self::assertGrant($refusal, $actor, $user, 'posts:edit');
        self::assertRevoke($refusal, $actor, $user, 'posts:read');
        self::assertSyncs($refusal, $actor, $user, ['posts:read', 'posts:edit']);
    }

    /**
     * A grantee whose rank cannot be read cannot be compared, so the change is
     * refused as uncomparable, a revocation included; with rank turned off,
     * rank stands in nobody's way, the unranked included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUncomparableSideFailsClosedAndRankCanBeTurnedOff(): void
    {
        $actor    = self::actor('admin', ['authorization:*' => []]);
        $external = new Reference('external', '1');
        $edit     = self::permission('posts:edit');

        $refusal = self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE, static fn (): int => self::grants()->revokePermission($external, $edit, $actor));

        self::assertEquals($actor->check(OperationResource::revoke(Actions::PERMISSION_REVOKE, $external, $edit, GrantScope::platform()))->reason, $refusal->getReason());

        config(['authorization.rank.enabled' => false]);

        $unranked = self::actor('unranked', ['authorization:*' => []], null);

        self::assertSame(0, self::grants()->revokePermission($external, $edit, $unranked));
        self::assertGrant(null, $unranked, self::user('user'), 'posts:edit');
    }

    /**
     * The rank a role grant would give the grantee counts as its rank: a grant
     * that would leave it equal to or senior to the actor is refused as rank,
     * and one that leaves it junior passes rank and is refused as unprovable,
     * role grants still waiting for a later release.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRankARoleGrantWouldGiveCounts(): void
    {
        $actor  = self::actor('admin', ['authorization:*' => []], 2);
        $user   = self::user('user');
        $senior = Role::query()->create(['name' => 'senior', 'rank' => 1]);
        $peer   = Role::query()->create(['name' => 'peer', 'rank' => 2]);
        $junior = Role::query()->create(['name' => 'junior', 'rank' => 7]);

        foreach ([$senior, $peer] as $role) {
            self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_RANK, static fn (): mixed => self::grants()->grantRole($user, $role, actor: $actor));
        }

        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_UNPROVABLE, static fn (): mixed => self::grants()->grantRole($user, $junior, actor: $actor));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $actor->check(OperationResource::grant(Actions::ROLE_GRANT, $user, $senior, GrantScope::platform()))->reason);
    }

    /**
     * A grant to the actor itself is refused as self unless it is also allowed
     * `authorization:administration.self`; rank is not weighed against itself,
     * and a revocation from itself only narrows, so it needs no right.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantToTheActorItselfNeedsTheSelfRight(): void
    {
        $actor  = self::actor('admin', [Actions::PERMISSION_GRANT => [], Actions::PERMISSION_REVOKE => [], 'posts:*' => []]);
        $self   = self::user('admin');
        $refuse = DecisionReason::ADMINISTRATION_SELF;

        self::assertGrant($refuse, $actor, $self, 'posts:edit');
        self::assertRevoke(null, $actor, $self, 'posts:*');

        $allowed = self::actor('allowed', [Actions::PERMISSION_GRANT => [], Actions::ADMINISTRATION_SELF => [], 'posts:*' => []]);

        self::assertGrant(null, $allowed, self::user('allowed'), 'posts:edit');
    }

    /**
     * A grant that reaches the tenants below its tenant needs authority that
     * itself reaches below: an actor holding the action in the tenant alone may
     * grant there, but not to the subtree.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNodeOnlyAuthorityCannotIssueASubtreeGrant(): void
    {
        [$parent] = $this->tree();

        $actor = self::actor('admin', [Actions::PERMISSION_GRANT => ['tenant' => $parent, 'subtree' => false], 'posts:*' => ['tenant' => $parent]]);
        $user  = self::user('user');

        $this->actAsTenant($parent);

        self::assertGrant(DecisionReason::ADMINISTRATION_SCOPE, $actor, $user, 'posts:edit', ['tenant' => $parent]);
        self::assertGrant(null, $actor, $user, 'posts:edit', ['tenant' => $parent, 'subtree' => false]);
    }

    /**
     * A grant to every application needs authority in every application: an
     * actor holding the action for one application may grant for it alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testApplicationLimitedAuthorityCannotIssueAnUnrestrictedGrant(): void
    {
        $actor = self::actor('admin', [Actions::PERMISSION_GRANT => ['application' => 'admin'], 'posts:*' => []]);
        $user  = self::user('user');

        self::assertGrant(DecisionReason::ADMINISTRATION_SCOPE, $actor, $user, 'posts:edit', ['on' => 'admin']);
        self::assertGrant(null, $actor, $user, 'posts:edit', ['on' => 'admin', 'application' => 'admin']);
    }

    /**
     * A platform-wide grant needs platform authority, which the grant's own
     * decision at platform scope asks for, and is made from the platform: one
     * made from a tenant edits a record the tenant does not own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformGrantNeedsPlatformAuthorityFromThePlatform(): void
    {
        [$parent] = $this->tree();

        $local = self::actor('local', [Actions::PERMISSION_GRANT => ['tenant' => $parent], 'posts:*' => []]);
        $wide  = self::actor('wide', [Actions::PERMISSION_GRANT => [], 'posts:*' => []]);
        $user  = self::user('user');

        self::assertGrant(DecisionReason::NO_MATCH, $local, $user, 'posts:edit');
        self::assertGrant(null, $wide, $user, 'posts:edit');

        $this->actAsTenant($parent);

        self::assertGrant(DecisionReason::ADMINISTRATION_OWNER, $wide, self::user('other'), 'posts:edit');
    }

    /**
     * A grant row held in an ancestor of the tenant the request is in cannot be
     * edited from it, even by an actor allowed there by a platform-wide grant:
     * only the owner edits; an ancestor's permission is still granted to a
     * grantee in the tenant itself, which edits the tenant's own row alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAncestorsRecordsCannotBeEditedFromADescendant(): void
    {
        [$parent, $child] = $this->tree();

        $actor  = self::actor('admin', ['authorization:*' => []]);
        $user   = self::user('user');
        $shared = Permission::query()->withoutGlobalScopes()->create(['name' => 'posts:share', ...self::ownedBy($parent)]);

        self::grants()->grantPermission($user, $shared, tenant: $parent);

        $this->actAsTenant($child);

        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_OWNER, static fn (): int => self::grants()->revokePermission($user, $shared, $actor, $parent));
        self::assertGrant(DecisionReason::ADMINISTRATION_OWNER, $actor, $user, 'posts:edit', ['tenant' => $parent]);
        self::assertGrant(null, $actor, $user, $shared, ['tenant' => $child]);
    }

    /**
     * An actor that holds the permission across the grant's reach and lifetime
     * may grant it without the grantable right, a wildcard holder included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHolderMayGrantWhatItHolds(): void
    {
        $actor    = self::actor('admin', [...self::granting(), 'posts:edit' => []]);
        $wildcard = self::actor('wildcard', [...self::granting(), 'posts:*' => []]);
        $user     = self::user('user');

        self::assertGrant(null, $actor, $user, 'posts:edit');
        self::assertGrant(null, $wildcard, self::user('other'), 'posts:edit');
        self::assertGrant(null, $wildcard, self::user('third'), 'posts:*');
        self::assertGrant(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, $user, 'posts:*');
        self::assertGrant(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, $user, 'posts:read');
    }

    /**
     * A grant reaching the tenants below its tenant needs the permission held
     * there by a grant that reaches below too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANodeOnlyHoldingCannotBeGrantedToTheSubtree(): void
    {
        [$parent] = $this->tree();

        $actor = self::actor('admin', [...self::granting(), 'posts:edit' => ['tenant' => $parent, 'subtree' => false]]);
        $user  = self::user('user');

        $this->actAsTenant($parent);

        self::assertGrant(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, $user, 'posts:edit', ['tenant' => $parent]);
        self::assertGrant(null, $actor, $user, 'posts:edit', ['tenant' => $parent, 'subtree' => false]);
    }

    /**
     * The actor's authority must last as long as the grant: a permanent grant
     * needs permanent authority, an expiring one authority lasting at least as
     * long; a role's grant of the permission lasts until the earlier of the
     * role's grant and the role's own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheActorsAuthorityMustOutlastTheGrant(): void
    {
        Carbon::setTestNow(Carbon::parse('2026-11-07 12:00:00', 'UTC'));

        $actor = self::actor('admin', [...self::granting(), 'posts:edit' => ['expires' => Carbon::now()->addDay()]]);
        $user  = self::user('user');

        self::assertGrant(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, $user, 'posts:edit');
        self::assertGrant(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, $user, 'posts:edit', ['expires' => Carbon::now()->addDays(2)]);
        self::assertGrant(null, $actor, $user, 'posts:edit', ['expires' => Carbon::now()->addHour()]);

        $editor = Role::query()->create(['name' => 'editor']);
        $holder = self::actor('holder', self::granting());

        app(RoleService::class)->grantPermission($editor, self::permission('posts:read'), Carbon::now()->addDays(3));
        self::grants()->grantRole(StubIdentity::query()->findOrFail('holder'), $editor, Carbon::now()->addDays(5));

        self::assertGrant(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $holder, $user, 'posts:read', ['expires' => Carbon::now()->addDays(4)]);
        self::assertGrant(null, $holder, $user, 'posts:read', ['expires' => Carbon::now()->addDays(2)]);
    }

    /**
     * Anything that denies or caps the actor and could limit the permission
     * fails the possession route, whether or not it applies now: a deny with a
     * condition, a boundary that does not allow the permission whole, and a
     * guardrail that touches it; a boundary allowing it whole does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnythingThatCouldLimitThePermissionFailsPossession(): void
    {
        $user = self::user('user');

        $denied = self::actor('denied', [...self::granting(), 'posts:*' => []]);

        StubIdentity::query()->findOrFail('denied')->attachPolicy(self::document('conditional', [
            ['effect' => 'deny', 'actions' => ['posts:edit'], 'conditions' => ['null' => ['request.ip' => false]]],
        ]));

        self::assertGrant(DecisionReason::ADMINISTRATION_UNPROVABLE, $denied, $user, 'posts:edit');
        self::assertGrant(DecisionReason::ADMINISTRATION_UNPROVABLE, $denied, $user, 'posts:*');
        self::assertGrant(null, $denied, $user, 'posts:read');

        $bounded = self::actor('bounded', [...self::granting(), 'posts:*' => []]);

        BoundaryService::instance()?->set(StubIdentity::query()->findOrFail('bounded'), self::document('bound', [
            ['effect' => 'allow', 'actions' => ['authorization:*', 'posts:read']],
            ['effect' => 'allow', 'actions' => ['posts:edit'], 'resources' => ['posts:mine:*']],
        ]));

        self::assertGrant(DecisionReason::ADMINISTRATION_UNPROVABLE, $bounded, $user, 'posts:edit');
        self::assertGrant(null, $bounded, $user, 'posts:read');
    }

    /**
     * A guardrail that touches the permission anywhere in the grant's reach
     * fails the possession route, though it never limits the check now.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardrailTouchingThePermissionFailsPossession(): void
    {
        $manager = self::actor('manager', [Actions::GUARDRAIL_MANAGE => []]);
        $actor   = self::actor('admin', [...self::granting(), 'posts:*' => []]);

        GuardrailService::instance()?->set(self::document('rail', [
            ['effect' => 'allow', 'actions' => ['*']],
            ['effect' => 'deny', 'actions' => ['posts:edit'], 'resources' => ['posts:secret:*']],
        ]), null, $manager);

        self::assertGrant(DecisionReason::ADMINISTRATION_UNPROVABLE, $actor, self::user('user'), 'posts:edit');
        self::assertGrant(null, $actor, self::user('user'), 'posts:read');
    }

    /**
     * A session cap that does not cover the permission fails the possession
     * route.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACapNotCoveringThePermissionFailsPossession(): void
    {
        $actor = self::actor('admin', [...self::granting(), 'posts:*' => []])->capped(['authorization:*', 'posts:read']);

        self::assertGrant(DecisionReason::ADMINISTRATION_UNPROVABLE, $actor, self::user('user'), 'posts:edit');
        self::assertGrant(null, $actor, self::user('user'), 'posts:read');
    }

    /**
     * An explicit grantable decision allows a delegation the actor does not
     * hold, on the descriptor naming the permission and the reach, so a policy
     * may allow exactly one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExplicitGrantabilityAllowsWithoutPossession(): void
    {
        $actor = self::actor('admin', self::granting());
        $user  = self::user('user');

        StubIdentity::query()->findOrFail('admin')->attachPolicy(self::document('delegates', [[
            'effect'     => 'allow',
            'actions'    => [Actions::PERMISSION_GRANTABLE],
            'resources'  => [OperationResource::TYPE . ':*'],
            'conditions' => ['eq' => ['resource.permission' => 'posts:edit']],
        ]]));

        self::assertGrant(null, $actor, $user, 'posts:edit');
        self::assertGrant(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, $user, 'posts:read');

        $descriptor = OperationResource::grant(Actions::PERMISSION_GRANT, $user, self::permission('posts:edit'), GrantScope::platform())->grantable();

        self::assertTrue($actor->decide(Actions::PERMISSION_GRANTABLE, $descriptor)->isAllowed());
    }

    /**
     * A shortening of a grant the grantee holds only narrows, so it needs no
     * possession; an extension widens, so it does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAShorteningNarrowsAndAnExtensionWidens(): void
    {
        Carbon::setTestNow(Carbon::parse('2026-11-07 12:00:00', 'UTC'));

        $actor = self::actor('admin', self::granting());
        $user  = self::user('user');

        self::grants()->grantPermission($user, self::permission('posts:edit'), Carbon::now()->addDays(3));

        self::assertGrant(null, $actor, $user, 'posts:edit', ['expires' => Carbon::now()->addDay()]);
        self::assertGrant(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, $user, 'posts:edit', ['expires' => Carbon::now()->addDays(5)]);
        self::assertGrant(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $actor, $user, 'posts:edit');
    }

    /**
     * A sync decides every change against the authority held before it, and is
     * atomic: one refused addition leaves nothing written and dispatches no
     * event, and a sync that takes away the actor's own authority still makes
     * the additions it was allowed beforehand.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABatchIsDecidedOnTheAuthorityHeldBeforeItAndIsAtomic(): void
    {
        $actor = self::actor('admin', [...self::granting(), 'posts:edit' => []]);
        $user  = self::user('user');

        $read = self::permission('posts:read');

        self::grants()->grantPermission($user, self::permission('posts:old'));

        $sync = static fn (): mixed => self::grants()->syncPermissions($user, ['posts:edit', $read], actor: $actor);

        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, $sync);
        self::assertSame(['posts:old'], $user->fresh()?->getPermissionNames());

        $self = self::actor('self', ['authorization:*' => []]);

        self::grants()->syncPermissions(StubIdentity::query()->findOrFail('self'), [self::permission('posts:edit')], actor: $self);

        self::assertSame(['posts:edit'], StubIdentity::query()->findOrFail('self')->getPermissionNames());
    }

    /**
     * Over random actors, grantees and grants, a screen deciding a direct grant
     * gets exactly the decision the grant service makes, allowed or refused for
     * the same reason.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAScreenAndTheServiceAgreeOverRandomGrants(): void
    {
        Carbon::setTestNow(Carbon::parse('2026-11-07 12:00:00', 'UTC'));
        \mt_srand(65);

        [$parent, $child] = $this->tree();

        $tenants = [null, $parent, $child];
        $names   = ['posts:edit', 'posts:read', 'posts:*'];

        $expiry = static fn (): ?Carbon => \mt_rand(0, 1) === 1 ? Carbon::now()->addDays(\mt_rand(1, 5)) : null;
        $scope  = static fn (int $from): array => \array_filter(
            ['tenant' => $tenants[\mt_rand($from, 2)], 'subtree' => \mt_rand(0, 1) === 1, 'expires' => $expiry()],
            static fn (mixed $value): bool => $value !== null,
        );

        for ($case = 0; $case < 24; $case++) {
            $holding = [Actions::PERMISSION_GRANT => $scope(0), $names[\mt_rand(0, 2)] => $scope(0)];
            $actor   = self::actor("actor-{$case}", $holding, [null, 1, 5][\mt_rand(0, 2)]);
            $grantee = self::user("grantee-{$case}", [null, 3][\mt_rand(0, 1)]);
            $options = $scope(1);

            $this->actAsTenant($options['tenant'] ?? null);

            self::assertScreenAgrees($actor, $grantee, self::permission($names[\mt_rand(0, 2)]), $options);
        }
    }

    /**
     * Assert a screen deciding the direct grant gets the decision the grant
     * service makes: both allowed, or both refused for the same reason.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $target
     * @param  array{tenant?: \Tests\Feature\Stubs\StubTenant, subtree?: bool, expires?: \Illuminate\Support\Carbon}  $options
     * @return void
     *
     * @throws \Throwable
     */
    private static function assertScreenAgrees(ActingContext $actor, StubIdentity $user, Permission $target, array $options): void
    {
        $tenant = $options['tenant'] ?? null;
        $scope  = new GrantScope($tenant === null ? null : Reference::of($tenant), null, ($options['subtree'] ?? true) || $tenant === null);
        $screen = $actor->check(OperationResource::grant(Actions::PERMISSION_GRANT, $user, $target, $scope, $options['expires'] ?? null));

        try {
            self::grants()->grantPermission($user, $target, $options['expires'] ?? null, $actor, $tenant, $options['subtree'] ?? true);
            $service = null;
        } catch (AuthorizationException $refusal) {
            $service = $refusal->getReason();
        }

        self::assertSame($screen->isAllowed() ? null : $screen->reason, $service);
    }

    /**
     * Assert the screen's decision of a direct grant of the permission and the
     * service's agree: both allowed, the row written, or both refused for the
     * reason, nothing written.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null  $refusal
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @param  array{tenant?: \Tests\Feature\Stubs\StubTenant, subtree?: bool, application?: string, expires?: \Illuminate\Support\Carbon, on?: string}  $options
     * @return void
     *
     * @throws \Throwable
     */
    private static function assertGrant(?DecisionReason $refusal, ActingContext $actor, StubIdentity $user, Permission|string $permission, array $options = []): void
    {
        $target = $permission instanceof Permission ? $permission : self::permission($permission);

        [$tenant, $subtree, $application, $expiresAt] = self::named($options);

        $scope  = new GrantScope($tenant === null ? null : Reference::of($tenant), $application, $subtree || $tenant === null);
        $screen = self::on($options, static fn (): Decision => $actor->check(OperationResource::grant(Actions::PERMISSION_GRANT, $user, $target, $scope, $expiresAt)));
        $write  = static fn (): mixed => self::grants()->grantPermission($user, $target, $expiresAt, $actor, $tenant, $subtree, $application);
        $grant  = static fn (): mixed => self::on($options, $write);

        self::assertInstanceOf(Decision::class, $screen);

        if ($refusal !== null) {
            self::assertSame($refusal, $screen->reason);
            self::assertDelegatedRefusal($refusal, $grant);

            return;
        }

        self::assertTrue($screen->isAllowed(), 'The screen refused it as ' . $screen->reason?->value);
        $grant();
        $rows = DB::table('authorizable_permissions')->where('authorizable_id', $user->id)->where('permission_id', $target->id);

        self::assertSame(1, ($tenant === null ? $rows->whereNull('tenant_id') : $rows->where('tenant_id', $tenant->getKey()))->count());
    }

    /**
     * Assert the revocation of the permission is refused for the reason, as a
     * screen deciding it is, or made.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null  $refusal
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  string  $permission
     * @return void
     *
     * @throws \Throwable
     */
    private static function assertRevoke(?DecisionReason $refusal, ActingContext $actor, StubIdentity $user, string $permission): void
    {
        $target = self::permission($permission);
        $screen = $actor->check(OperationResource::revoke(Actions::PERMISSION_REVOKE, $user, $target, GrantScope::platform()));

        if ($refusal !== null) {
            self::assertSame($refusal, $screen->reason);
            self::assertDelegatedRefusal($refusal, static fn (): int => self::grants()->revokePermission($user, $target, $actor));

            return;
        }

        self::assertTrue($screen->isAllowed());
        self::assertSame(1, self::grants()->revokePermission($user, $target, $actor));
    }

    /**
     * Assert the sync of the grantee's direct permissions to the names is
     * refused for the reason, or made.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null  $refusal
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  list<string>  $permissions
     * @return void
     *
     * @throws \Throwable
     */
    private static function assertSyncs(?DecisionReason $refusal, ActingContext $actor, StubIdentity $user, array $permissions): void
    {
        $targets = \array_map(self::permission(...), $permissions);
        $sync    = static fn (): mixed => self::grants()->syncPermissions($user, $targets, actor: $actor);

        if ($refusal !== null) {
            self::assertDelegatedRefusal($refusal, $sync);

            return;
        }

        $sync();

        self::assertEqualsCanonicalizing($permissions, $user->fresh()?->getPermissionNames());
    }

    /**
     * Return the scope the options name: the tenant, or none, whether the grant
     * reaches below it, the application, or none, and the expiry, or none.
     *
     * @param  array{tenant?: \Tests\Feature\Stubs\StubTenant, subtree?: bool, application?: string, expires?: \Illuminate\Support\Carbon}  $options
     * @return array{\Tests\Feature\Stubs\StubTenant|null, bool, string|null, \Illuminate\Support\Carbon|null}
     */
    private static function named(array $options): array
    {
        return [$options['tenant'] ?? null, $options['subtree'] ?? true, $options['application'] ?? null, $options['expires'] ?? null];
    }

    /**
     * Run the call in the request's application the options name, if any.
     *
     * @param  array{on?: string}  $options
     * @param  \Closure(): mixed  $call
     * @return mixed
     */
    private static function on(array $options, \Closure $call): mixed
    {
        if (!isset($options['on'])) {
            return $call();
        }

        $tenant = TenantScope::currentChain()->tenant();

        return TenantScope::within($tenant, $options['on'], $call);
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
     * Return the acting context of a new identity granted each permission, in
     * the scope its options name, and a platform role of the rank, or none for
     * null.
     *
     * @param  string  $id
     * @param  array<string, array{tenant?: \Tests\Feature\Stubs\StubTenant, subtree?: bool, application?: string, expires?: \Illuminate\Support\Carbon}>  $grants
     * @param  int|null  $rank
     * @return \SineMacula\Laravel\Authorization\Administration\ActingContext
     *
     * @throws \Throwable
     */
    private static function actor(string $id, array $grants, ?int $rank = 1): ActingContext
    {
        $actor = self::user($id, $rank);

        foreach ($grants as $name => $scope) {
            [$tenant, $subtree, $application, $expiresAt] = self::named($scope);

            self::grants()->grantPermission($actor, self::permission($name), $expiresAt, null, $tenant, $subtree, $application);
        }

        return ActingContext::for($actor);
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
            self::grants()->grantRole($user, Role::query()->firstOrCreate(['name' => 'rank-' . $rank], ['rank' => $rank]));
        }

        return $user;
    }

    /**
     * Return the administration actions a granting administrator holds, each
     * platform-wide.
     *
     * @return array<string, array{}>
     */
    private static function granting(): array
    {
        return \array_fill_keys(self::GRANTING, []);
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
    private static function document(string $name, array $statements): Policy
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
}
