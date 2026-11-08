<?php

declare(strict_types = 1);

namespace Tests\Feature\Preview;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Preview\PreviewAdmission;
use SineMacula\Laravel\Authorization\Preview\PreviewResource;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\PreviewsSubjects;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;
use Tests\Fixtures\QueryScoping\TenantScopedPost;
use Tests\TestCase;

/**
 * Feature tests for `PreviewAdmission`, the admissions of a preview's use
 * (N84): the right to preview is decided as the caller, as an ordinary check,
 * in every scope one of the use's decisions about the target is made in, the
 * preview's tenant, a resource's own tenant below it, the tenants just below an
 * anchor or the platform, each once in the use; applications restrict who may
 * be previewed, and where, by policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PreviewAdmission::class)]
final class PreviewAdmissionTest extends TestCase
{
    use CatchesRefusals, PreviewsSubjects, ReadsDispatchedEvents;

    /**
     * A preview in a tenant needs the right there, decided in that tenant: a
     * caller granted it in the tenant previews in it, while one granted it in
     * another tenant does not, whichever tenant it signed in at.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantPreviewNeedsTheRightInTheTenant(): void
    {
        $tenant = self::tenant('t1');
        $other  = self::tenant('t2');
        $caller = self::previewer('previewer', false);
        $target = self::target();

        self::grants()->grantPermission($caller, self::permission(PackagePermissions::SUBJECT_PREVIEW), tenant: $tenant);

        $manager = $this->signIn($caller, 'session-1', $tenant);

        self::assertTrue($manager->previewFor($target)->can('posts:read'));
        self::assertRefused(DecisionReason::NO_MATCH, static fn (): mixed => $manager->previewFor($target, AuthorizationScope::tenant($other)));

        $elsewhere = $this->signIn($caller, 'session-1', $other);

        self::assertRefused(DecisionReason::NO_MATCH, static fn (): mixed => $elsewhere->previewFor($target));
    }

    /**
     * A parent's right that reaches its subtree admits a preview in a child,
     * while a right held at the parent's node alone does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAParentsSubtreeRightAdmitsAPreviewInAChild(): void
    {
        $parent = self::tenant('parent');
        $child  = self::tenant('child');
        $target = self::target();
        $right  = self::permission(PackagePermissions::SUBJECT_PREVIEW);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($parent)));

        $subtree = self::previewer('subtree', false);
        $node    = self::previewer('node', false);

        self::grants()->grantPermission($subtree, $right, tenant: $parent);
        self::grants()->grantPermission($node, $right, tenant: $parent, includeSubtree: false);

        self::assertTrue($this->signIn($subtree, 'session-1', $parent)->previewFor($target, AuthorizationScope::tenant($child))->can('posts:read'));
        self::assertRefused(DecisionReason::NO_MATCH, fn (): mixed => $this->signIn($node, 'session-1', $parent)->previewFor($target, AuthorizationScope::tenant($child)));
        self::assertTrue($this->signIn($node, 'session-1', $parent)->previewFor($target)->can('posts:read'));
    }

    /**
     * A platform preview is admitted at platform scope, where every decision it
     * makes is made: a deny the caller holds in one tenant applies there alone,
     * as for any check at platform scope, so it refuses a preview in that
     * tenant, but not one at the platform.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformPreviewIsAdmittedAtPlatformScope(): void
    {
        $denied = self::tenant('denied');
        $caller = self::previewer();
        $target = self::target();

        $role   = Role::query()->create(['name' => 'no-previews']);
        $policy = Policy::query()->create(['name' => 'no-previews', 'document' => ['statements' => [['effect' => 'deny', 'actions' => [PackagePermissions::SUBJECT_PREVIEW]]]]]);

        self::grants()->attachPolicy($role, $policy);
        self::grants()->grantRole($caller, $role, tenant: $denied);

        $manager = $this->signIn($caller);
        $preview = $manager->previewFor($target);

        self::assertTrue($preview->can('posts:read'));
        self::assertTrue($preview->can('posts:read', ResourceReference::record('post', '1', Reference::of($denied))));
        self::assertRefused(DecisionReason::EXPLICIT_DENY, static fn (): mixed => $manager->previewFor($target, AuthorizationScope::tenant($denied)));
    }

    /**
     * A conditional deny at platform scope refuses the previews it matches
     * alone: one naming another target leaves the preview admitted, and one
     * naming this target refuses it, as the preview is built and at a later use
     * alike.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConditionalDenyAtPlatformScopeRefusesOnlyTheTargetsItMatches(): void
    {
        $caller = self::previewer();
        $junior = self::target('junior');
        $senior = self::target('senior');

        $manager = $this->signIn($caller);
        $later   = $manager->previewFor($senior);

        $deny = ['effect' => 'deny', 'actions' => [PackagePermissions::SUBJECT_PREVIEW], 'conditions' => ['eq' => ['resource.target_id' => 'senior']]];

        self::attachStatements($caller, 'not-the-senior', [$deny]);

        self::assertTrue($manager->previewFor($junior)->can('posts:read'));
        self::assertRefused(DecisionReason::EXPLICIT_DENY, static fn (): mixed => $manager->previewFor($senior));
        self::assertRefused(DecisionReason::EXPLICIT_DENY, static fn (): mixed => $later->can('posts:read'));
    }

    /**
     * A tenant preview reaches the tenants below it, so each decision about a
     * child tenant's resource is admitted in that tenant: a caller allowed the
     * right in the parent but denied it in the child is refused every answer
     * there, through a check, an explanation, a batch, a listing and a query,
     * while it is still answered in the parent; one not denied in the child is
     * answered in both.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachDecisionInAChildTenantIsAdmittedInThatTenant(): void
    {
        [$parent, $child] = self::tree();

        $right  = self::permission(PackagePermissions::SUBJECT_PREVIEW);
        $denied = self::previewer('denied', false);
        $other  = self::previewer('allowed', false);
        $target = self::target('target', []);

        foreach ([$denied, $other] as $caller) {
            self::grants()->grantPermission($caller, $right, tenant: $parent);
        }

        self::grants()->grantPermission($target, self::permission('posts:view'), tenant: $parent);
        self::denyInTenant($denied, $child);

        [$own, $below] = self::posts($parent, $child);

        $preview = $this->signIn($denied, 'session-1', $parent)->previewFor($target);
        $refused = [
            static fn (): mixed => $preview->can('posts:view', $below),
            static fn (): mixed => $preview->explain('posts:view', $below),
            static fn (): mixed => $preview->checkMany([new CheckInput('posts:view', $own), new CheckInput('posts:view', $below)]),
            static fn (): mixed => $preview->permissionsFor(null, AuthorizationScope::tenant($parent)->withResource($below)),
            static fn (): mixed => self::scoped($preview)->get(),
        ];

        self::assertTrue($preview->can('posts:view', $own));

        foreach ($refused as $use) {
            self::assertRefused(DecisionReason::EXPLICIT_DENY, $use);
        }

        $allowed = $this->signIn($other, 'session-1', $parent)->previewFor($target);

        self::assertTrue($allowed->can('posts:view', $below));
        self::assertSame(['own', 'below'], self::scoped($allowed)->orderBy('id')->pluck('title')->all());
    }

    /**
     * An application restricts where a preview is answered by policy, on the
     * built-in `resource.tenant.type` and `resource.tenant.id` of the scope a
     * decision is made in, and on `resource.application`: a deny naming the
     * child tenant refuses the answers made there alone, and one naming an
     * application refuses previews there alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPoliciesRestrictWhereAPreviewIsAnswered(): void
    {
        $parent = self::tenant('parent');
        $child  = self::tenant('child');
        $caller = self::previewer();
        $target = self::target();

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($parent)));

        self::attachStatements($caller, 'not-there', [
            [
                'effect'     => 'deny',
                'actions'    => [PackagePermissions::SUBJECT_PREVIEW],
                'conditions' => ['eq' => ['resource.tenant.id' => 'child', 'resource.tenant.type' => $child->getMorphClass()]],
            ],
            ['effect' => 'deny', 'actions' => [PackagePermissions::SUBJECT_PREVIEW], 'conditions' => ['eq' => ['resource.application' => 'billing']]],
        ]);

        $manager = $this->signIn($caller, 'session-1', $parent, 'admin');
        $preview = $manager->previewFor($target);

        self::assertTrue($preview->can('posts:read', ResourceReference::record('post', '1', Reference::of($parent))));
        self::assertRefused(DecisionReason::EXPLICIT_DENY, static fn (): mixed => $preview->can('posts:read', ResourceReference::record('post', '2', Reference::of($child))));
        self::assertTrue($manager->previewFor($target, AuthorizationScope::tenant($parent, 'admin'))->can('posts:read'));
        self::assertRefused(DecisionReason::EXPLICIT_DENY, static fn (): mixed => $manager->previewFor($target, AuthorizationScope::tenant($parent, 'billing')));
    }

    /**
     * The rows just below a tenant are decided just below it, so a query
     * through a preview needs the right to reach the tenants below: a caller
     * holding it at the parent's node alone is answered about the parent's own
     * resource, but refused the query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRowsBelowATenantNeedTheRightBelowIt(): void
    {
        [$parent, $child] = self::tree();

        $caller = self::previewer('node', false);
        $target = self::target('target', []);

        self::grants()->grantPermission($caller, self::permission(PackagePermissions::SUBJECT_PREVIEW), tenant: $parent, includeSubtree: false);
        self::grants()->grantPermission($target, self::permission('posts:view'), tenant: $parent);

        [$own] = self::posts($parent, $child);

        $preview = $this->signIn($caller, 'session-1', $parent)->previewFor($target);

        self::assertTrue($preview->can('posts:view', $own));
        self::assertRefused(DecisionReason::NO_MATCH, static fn (): mixed => self::scoped($preview)->get());
    }

    /**
     * A resource of a tenant outside a tenant preview's is decided at platform
     * scope, so its answer is admitted there: a caller holding the right in its
     * own tenant alone is refused it, through a check and a query, until it
     * holds the right platform-wide.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOutsideResourceIsAnsweredOnlyWithThePlatformRight(): void
    {
        $t1     = self::tenant('t1');
        $t2     = self::tenant('t2');
        $caller = self::previewer('previewer', false);
        $target = self::target('target', ['posts:view']);
        $right  = self::permission(PackagePermissions::SUBJECT_PREVIEW);

        self::grants()->grantPermission($caller, $right, tenant: $t1);

        [$own, $outside] = self::posts($t1, $t2);

        $manager = $this->signIn($caller, 'session-1', $t1);
        $preview = $manager->previewFor($target);

        self::assertTrue($preview->can('posts:view', $own));
        self::assertRefused(DecisionReason::NO_MATCH, static fn (): mixed => $preview->can('posts:view', $outside));
        self::assertRefused(DecisionReason::NO_MATCH, static fn (): mixed => self::scoped($preview)->get());

        self::grants()->grantPermission($caller, $right);

        self::assertTrue($preview->can('posts:view', $outside));
        self::assertSame(['own', 'below'], self::scoped($preview)->orderBy('id')->pluck('title')->all());
    }

    /**
     * Each scope a use's decisions are made in is admitted once in the use: a
     * batch over fifty resources of the preview's tenant is admitted once, one
     * over fifty of a child tenant once more for the child, and the next use is
     * admitted afresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachScopeIsAdmittedOncePerUse(): void
    {
        $parent = self::tenant('parent');
        $child  = self::tenant('child');
        $caller = self::previewer();
        $target = self::target();

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($parent)));

        Event::fake([DecisionEvaluated::class]);

        $preview = $this->signIn($caller, 'session-1', $parent)->previewFor($target);
        $checks  = static fn (StubTenant $tenant): array => \array_map(
            static fn (int $key): CheckInput => new CheckInput('posts:read', ResourceReference::record('post', (string) $key, Reference::of($tenant))),
            \range(1, 50),
        );

        self::assertSame([1, 0], self::counted());
        self::assertCount(50, \array_filter($preview->checkMany($checks($parent)), static fn ($decision): bool => $decision->isAllowed()));
        self::assertSame([2, 50], self::counted());

        $preview->checkMany($checks($child));

        self::assertSame([4, 100], self::counted());

        $preview->checkMany($checks($parent));

        self::assertSame([5, 150], self::counted());
    }

    /**
     * A preview is decided in its own application too: a right held for one
     * application admits a preview there, but not for another application nor
     * for none, which needs the right for every application.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreviewNeedsTheRightInItsApplication(): void
    {
        $caller = self::previewer('previewer', false);
        $target = self::target();

        self::grants()->grantPermission($caller, self::permission(PackagePermissions::SUBJECT_PREVIEW), application: 'admin');

        $manager = $this->signIn($caller, 'session-1', null, 'admin');

        self::assertTrue($manager->previewFor($target)->can('posts:read'));
        self::assertRefused(DecisionReason::NO_MATCH, static fn (): mixed => $manager->previewFor($target, AuthorizationScope::platform()));
        self::assertRefused(DecisionReason::NO_MATCH, static fn (): mixed => $manager->previewFor($target, AuthorizationScope::platform('billing')));
    }

    /**
     * An application restricts who may be previewed by policy, on the preview
     * resource's attributes or its reference: a deny on one target's key, its
     * identity or its reference, refuses that target alone, in a tenant and at
     * the platform alike, and no rank rule applies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPoliciesRestrictWhoMayBePreviewed(): void
    {
        $tenant = self::tenant('t1');
        $caller = self::previewer();
        $senior = self::target('senior');
        $junior = self::target('junior');
        $other  = self::target('other');

        self::attachStatements($caller, 'not-the-senior', [
            ['effect' => 'deny', 'actions' => [PackagePermissions::SUBJECT_PREVIEW], 'conditions' => ['eq' => ['resource.target_id' => 'senior']]],
            ['effect' => 'deny', 'actions' => [PackagePermissions::SUBJECT_PREVIEW], 'resources' => [PreviewResource::TYPE . ':' . $other->getMorphClass() . ':other']],
            ['effect' => 'deny', 'actions' => [PackagePermissions::SUBJECT_PREVIEW], 'conditions' => ['eq' => ['resource.identity_id' => 'protected']]],
        ]);

        $protected = new Subject($junior, StubIdentity::query()->create(['id' => 'protected']));

        $manager = $this->signIn($caller, 'session-1', $tenant);

        self::assertRefused(DecisionReason::EXPLICIT_DENY, static fn (): mixed => $manager->previewFor($senior));
        self::assertRefused(DecisionReason::EXPLICIT_DENY, static fn (): mixed => $manager->previewFor($other));
        self::assertRefused(DecisionReason::EXPLICIT_DENY, static fn (): mixed => $manager->previewFor($protected));
        self::assertTrue($manager->previewFor($junior)->can('posts:read'));
        self::assertTrue($this->signIn($caller)->previewFor($junior)->can('posts:read'));
        self::assertRefused(DecisionReason::EXPLICIT_DENY, fn (): mixed => $this->signIn($caller)->previewFor($senior));
    }

    /**
     * A right to preview that needs a step-up the caller has not met refuses
     * the preview with `AuthorizationException`, as
     * `insufficient_authentication`, never with the step-up exception, so a
     * refusal always has the one shape; it carries the caller's own decision,
     * the one recorded, with the requirement it names.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnmetStepUpRefusesThePreviewAsAnAuthorizationException(): void
    {
        $caller = self::previewer('previewer', false);
        $target = self::target();

        self::attachStatements($caller, 'stepped-up-preview', [self::requiring(PackagePermissions::SUBJECT_PREVIEW)]);

        $manager = $this->signIn($caller, 'session-1', null, null, new StubRequirementChecker(RequirementResult::unmet(['multifactor'])));
        $refusal = self::refusalOf(static fn (): mixed => $manager->previewFor($target));

        self::assertSame(AuthorizationException::class, $refusal::class);
        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $refusal->getReason());
        self::assertSame($manager->lastDecision(), $refusal->getDecision());
        self::assertNotSame([], $refusal->getDecision()?->requirements);
    }

    /**
     * Assert the callback is refused with the reason, as a preview is.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private static function assertRefused(DecisionReason $reason, \Closure $callback): void
    {
        try {
            $callback();
            self::fail('The preview was admitted.');
        } catch (AuthorizationException $exception) {
            self::assertSame($reason, $exception->getReason());
        }
    }

    /**
     * Return how many admissions and how many decisions about a target have
     * been reported so far.
     *
     * @return array{int, int}
     */
    private static function counted(): array
    {
        $events     = self::dispatchedEvents(DecisionEvaluated::class);
        $admissions = \array_filter($events, static fn (DecisionEvaluated $event): bool => $event->previewer === null && $event->action === PackagePermissions::SUBJECT_PREVIEW);

        return [\count($admissions), \count($events) - \count($admissions)];
    }

    /**
     * Return a parent tenant and a child of it, in a tree of subtrees that
     * queries read too.
     *
     * @return array{\Tests\Feature\Stubs\StubTenant, \Tests\Feature\Stubs\StubTenant}
     */
    private function tree(): array
    {
        $parent = self::tenant('parent');
        $child  = self::tenant('child');

        $this->app?->instance(TenantTree::class, new ClosureTenantTree);

        ClosureTenantTree::add(Reference::of($parent));
        ClosureTenantTree::add(Reference::of($child), Reference::of($parent));

        return [$parent, $child];
    }

    /**
     * Return a post of each tenant, titled `own` and `below`.
     *
     * @param  \Tests\Feature\Stubs\StubTenant  $own
     * @param  \Tests\Feature\Stubs\StubTenant  $below
     * @return array{\Tests\Fixtures\QueryScoping\TenantScopedPost, \Tests\Fixtures\QueryScoping\TenantScopedPost}
     */
    private static function posts(StubTenant $own, StubTenant $below): array
    {
        $type = $own->getMorphClass();

        return [
            TenantScopedPost::query()->create(['title' => 'own', 'tenant_type' => $type, 'tenant_id' => $own->getKey()]),
            TenantScopedPost::query()->create(['title' => 'below', 'tenant_type' => $type, 'tenant_id' => $below->getKey()]),
        ];
    }

    /**
     * Deny the caller the right to preview in the tenant, through a role it
     * holds there.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $caller
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @return void
     *
     * @throws \Throwable
     */
    private static function denyInTenant(StubIdentity $caller, StubTenant $tenant): void
    {
        $name   = 'no-previews-' . Reference::of($tenant)->id;
        $role   = Role::query()->create(['name' => $name]);
        $policy = Policy::query()->create(['name' => $name, 'document' => ['statements' => [['effect' => 'deny', 'actions' => [PackagePermissions::SUBJECT_PREVIEW]]]]]);

        self::grants()->attachPolicy($role, $policy);
        self::grants()->grantRole($caller, $role, tenant: $tenant);
    }

    /**
     * Return the posts query scoped to `posts:view` through the manager.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @return \Illuminate\Database\Eloquent\Builder<\Tests\Fixtures\QueryScoping\TenantScopedPost>
     */
    private static function scoped(AuthorizationManager $manager): Builder
    {
        /** @var \Illuminate\Database\Eloquent\Builder<\Tests\Fixtures\QueryScoping\TenantScopedPost> */
        return TenantScopedPost::query()->whereAuthorized('posts:view', [], $manager); // @phpstan-ignore method.notFound
    }

    /**
     * Create a stub tenant with the id.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubTenant
     */
    private static function tenant(string $id): StubTenant
    {
        return StubTenant::query()->create(['id' => $id, 'name' => $id]);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        $service = GrantService::instance();

        self::assertInstanceOf(GrantService::class, $service);

        return $service;
    }
}
