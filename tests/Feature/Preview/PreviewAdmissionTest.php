<?php

declare(strict_types = 1);

namespace Tests\Feature\Preview;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
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
use Tests\Concerns\PreviewsSubjects;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `PreviewAdmission`, the reach of a preview's admission
 * (N84): the right to preview is decided as the caller at the preview's node,
 * its tenant or the platform, in its application, and a platform preview is
 * refused wherever anything could limit the right; applications restrict who
 * may be previewed by policy.
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
    use PreviewsSubjects;

    /**
     * A preview in a tenant needs the right there: a caller granted it in the
     * tenant previews in it, while one granted it in another tenant, or in a
     * tenant outside the request's, does not.
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
        self::assertRefused(DecisionReason::TENANT_SCOPE, static fn (): mixed => $manager->previewFor($target, AuthorizationScope::tenant($other)));

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
     * A platform preview reaches every tenant: a caller allowed the right at
     * the platform but denied it in one tenant may preview in no platform
     * scope, as `administration.scope`, while it still previews in another
     * tenant, where nothing limits it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformPreviewIsRefusedWhereTheRightIsDeniedInATenant(): void
    {
        $denied = self::tenant('denied');
        $other  = self::tenant('other');
        $caller = self::previewer();
        $target = self::target();

        self::assertTrue($this->signIn($caller)->previewFor($target)->can('posts:read'));

        $role   = Role::query()->create(['name' => 'no-previews']);
        $policy = Policy::query()->create(['name' => 'no-previews', 'document' => ['statements' => [['effect' => 'deny', 'actions' => [PackagePermissions::SUBJECT_PREVIEW]]]]]);

        self::grants()->attachPolicy($role, $policy);
        self::grants()->grantRole($caller, $role, tenant: $denied);

        $manager = $this->signIn($caller);

        try {
            $manager->previewFor($target);
            self::fail('The platform preview was admitted.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, $exception->getReason());
            self::assertSame(DecisionStage::ADMINISTRATION, $exception->getDecision()?->stage);
            self::assertSame('administration.scope', $exception->getDecision()->trace[\count($exception->getDecision()->trace) - 1]->cap);
        }

        self::assertTrue($manager->previewFor($target, AuthorizationScope::tenant($other))->can('posts:read'));
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
        self::assertRefused(DecisionReason::ADMINISTRATION_SCOPE, static fn (): mixed => $manager->previewFor($target, AuthorizationScope::platform()));
        self::assertRefused(DecisionReason::ADMINISTRATION_SCOPE, static fn (): mixed => $manager->previewFor($target, AuthorizationScope::platform('billing')));
    }

    /**
     * An application restricts who may be previewed by policy, on the preview
     * resource's attributes or its reference: in a tenant, a deny on one
     * target's key, its identity or its reference, refuses that target alone,
     * and no rank rule applies; at the platform, which every tenant's limits
     * reach, such a deny refuses every preview.
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
        self::assertRefused(DecisionReason::ADMINISTRATION_SCOPE, fn (): mixed => $this->signIn($caller)->previewFor($junior));
    }

    /**
     * An admitted preview records one satisfied step at the administration
     * stage; a refusal, another action, another resource and no resource are
     * returned as they are, and nothing further is decided for them.
     *
     * @return void
     */
    public function testOnlyAnAllowedRightOnAPreviewIsWeighed(): void
    {
        $preview = (new PreviewResource(new Reference('user', '1'), null, new Reference('tenant', 'a'), null))->toResourceReference();
        $asked   = new \ArrayObject;
        $checks  = $this->checks($asked);
        $allow   = Decision::allow(DecisionStage::ALLOW);
        $deny    = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);

        self::assertSame($deny, PreviewAdmission::weigh($deny, PackagePermissions::SUBJECT_PREVIEW, $preview, $checks));
        self::assertSame($allow, PreviewAdmission::weigh($allow, 'posts:read', $preview, $checks));
        self::assertSame($allow, PreviewAdmission::weigh($allow, PackagePermissions::SUBJECT_PREVIEW, ResourceReference::record('post', '1'), $checks));
        self::assertSame($allow, PreviewAdmission::weigh($allow, PackagePermissions::SUBJECT_PREVIEW, null, $checks));
        self::assertCount(0, $asked);

        $admitted = PreviewAdmission::weigh($allow, PackagePermissions::SUBJECT_PREVIEW, $preview, $checks);

        self::assertTrue($admitted->isAllowed());
        self::assertCount(1, $asked);
        self::assertSame(DecisionStage::ADMINISTRATION, $admitted->trace[\count($admitted->trace) - 1]->stage);
        self::assertSame(TraceOutcome::SATISFIED, $admitted->trace[\count($admitted->trace) - 1]->outcome);
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
     * Return further checks allowing every check, counting each one asked.
     *
     * @param  \ArrayObject<int, string>  $asked
     * @return \SineMacula\Laravel\Authorization\Administration\FurtherChecks
     */
    private function checks(\ArrayObject $asked): FurtherChecks
    {
        $decide = static function (string $action) use ($asked): Decision {
            $asked[] = $action;

            return Decision::allow(DecisionStage::ALLOW);
        };

        $actor = StubIdentity::query()->create(['id' => 'actor']);

        return new FurtherChecks(new Subject($actor, $actor), $decide, static fn (): null => null);
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
