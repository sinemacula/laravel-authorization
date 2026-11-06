<?php

declare(strict_types = 1);

namespace Tests\Feature\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\SessionCapResolver;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubSessionPolicySource;
use Tests\Feature\Stubs\SuspendableIdentity;
use Tests\TestCase;

/**
 * Feature tests for the decision pipeline the authorization manager decides
 * every check through: the admission of the subject, the resource and its
 * tenant, the sources it gathers, its policy override and its caps.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DecisionPipeline::class)]
final class DecisionPipelineTest extends TestCase
{
    /**
     * Tear down Mockery instances after every test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * No subject is denied as unresolved at the subject stage, before any
     * policy or resource is read.
     *
     * @return void
     */
    public function testNoSubjectIsDeniedBeforeAnythingIsRead(): void
    {
        $policies = \Mockery::mock(PolicyResolver::class);
        $policies->shouldNotReceive('policiesFor');

        $decision = (new DecisionPipeline(new PolicyEvaluator, $policies))->decide(null, 'posts:read', false, []);

        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $decision->reason);
        self::assertSame(DecisionStage::SUBJECT, $decision->stage);
        self::assertSame([], $decision->trace);
    }

    /**
     * An inactive subject is denied at the subject stage, whatever it holds.
     *
     * @return void
     */
    public function testAnInactiveSubjectIsDeniedAtTheSubjectStage(): void
    {
        $user = SuspendableIdentity::create(['id' => 'suspended']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        $user->suspended = true;

        $decision = $this->pipeline()->decide(new Subject($user, $user), 'posts:read', null, []);

        self::assertSame(DecisionReason::SUBJECT_INACTIVE, $decision->reason);
        self::assertSame(DecisionStage::SUBJECT, $decision->stage);
    }

    /**
     * A resource that cannot be identified is denied at the resource stage,
     * before the grants are read.
     *
     * @return void
     */
    public function testAnUnidentifiableResourceIsDeniedAtTheResourceStage(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $policies = \Mockery::mock(PolicyResolver::class);
        $policies->shouldNotReceive('policiesFor');

        $decision = (new DecisionPipeline(new PolicyEvaluator, $policies))->decide(new Subject($user, $user), 'posts:read', false, []);

        self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, $decision->reason);
        self::assertSame(DecisionStage::RESOURCE, $decision->stage);
    }

    /**
     * A tenant-owned resource outside the scope is denied at the tenant stage,
     * even with a statement that allows it; with no resource, or one with no
     * tenant, the statement decides.
     *
     * @return void
     */
    public function testATenantOwnedResourceOutsideTheScopeIsDeniedAtTheTenantStage(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $subject  = new Subject($user, $user);
        $pipeline = $this->pipeline()->withPolicies([self::allowing('posts:read')]);

        $outside = $pipeline->decide($subject, 'posts:read', ResourceReference::record('posts', '7', new Reference('org', 'org-1')), []);

        self::assertSame(DecisionReason::TENANT_SCOPE, $outside->reason);
        self::assertSame(DecisionStage::TENANT, $outside->stage);
        self::assertTrue($pipeline->decide($subject, 'posts:read', ResourceReference::record('posts', '7'), [])->isAllowed());
        self::assertTrue($pipeline->decide($subject, 'posts:read', null, [])->isAllowed());
    }

    /**
     * A permission the subject holds allows at the allow stage, its step naming
     * the permission.
     *
     * @return void
     */
    public function testAHeldPermissionAllows(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        $decision = $this->pipeline()->decide(new Subject($user, $user), 'posts:read', null, []);

        self::assertTrue($decision->isAllowed());
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertEquals(new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, 'posts:read'), $decision->trace[3]);
        self::assertSame(DecisionReason::NO_MATCH, $this->pipeline()->decide(new Subject($user, $user), 'posts:delete', null, [])->reason);
    }

    /**
     * The policies come from the resolver, the subject's identity and the
     * resource: the subject's allow, the identity's deny and the resource's
     * deny each count, and without a resource policy resolver the resource's
     * are not read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePoliciesComeFromTheResolverTheIdentityAndTheResource(): void
    {
        $principal = StubIdentity::create(['id' => 'account-1']);
        $identity  = StubSecondIdentity::create(['id' => 'person-1']);
        $subject   = new Subject($principal, $identity);
        $post      = ResourceReference::record('posts', '7');

        $principal->attachPolicy(self::stored('editing', [['effect' => 'allow', 'actions' => ['posts:*']]]));
        $identity->attachPolicy(self::stored('no-publishing', [['effect' => 'deny', 'actions' => ['posts:publish']]]));
        self::resourcePolicies()->attach(self::stored('locked', [['effect' => 'deny', 'actions' => ['posts:edit']]]), ['posts', 7]);

        $pipeline = $this->pipeline();

        self::assertTrue($pipeline->decide($subject, 'posts:read', $post, [])->isAllowed());
        self::assertSame(DecisionReason::EXPLICIT_DENY, $pipeline->decide($subject, 'posts:publish', $post, [])->reason);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $pipeline->decide($subject, 'posts:edit', $post, [])->reason);

        $withoutResources = new DecisionPipeline(new PolicyEvaluator, new DefaultPolicyResolver);

        self::assertTrue($withoutResources->decide($subject, 'posts:edit', $post, [])->isAllowed());
    }

    /**
     * An override replaces the policies alone, in a new pipeline, reindexed:
     * the subject's and the resource's policies are not read, its permissions
     * still count, and the original pipeline is unchanged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOverrideReplacesThePoliciesAloneInANewPipeline(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $subject = new Subject($user, $user);
        $post    = ResourceReference::record('posts', '7');

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $user->attachPolicy(self::stored('editing', [['effect' => 'allow', 'actions' => ['posts:edit']]]));
        self::resourcePolicies()->attach(self::stored('locked', [['effect' => 'deny', 'actions' => ['posts:read']]]), ['posts', 7]);

        $pipeline   = $this->pipeline();
        $overridden = $pipeline->withPolicies([3 => self::allowing('posts:publish')]);
        $publish    = $overridden->decide($subject, 'posts:publish', $post, []);

        self::assertNotSame($pipeline, $overridden);
        self::assertTrue($publish->isAllowed());
        self::assertSame(0, $publish->statements[0]->index);
        self::assertSame('override', $publish->statements[0]->policy);
        self::assertSame(DecisionReason::NO_MATCH, $overridden->decide($subject, 'posts:edit', $post, [])->reason);
        self::assertTrue($overridden->decide($subject, 'posts:read', $post, [])->isAllowed());
        self::assertTrue($pipeline->decide($subject, 'posts:edit', $post, [])->isAllowed());
        self::assertSame(DecisionReason::EXPLICIT_DENY, $pipeline->decide($subject, 'posts:read', $post, [])->reason);
    }

    /**
     * Caps intersect, in a new pipeline, and the original pipeline is uncapped:
     * an action no cap covers is denied as a session policy.
     *
     * @return void
     */
    public function testCapsIntersectInANewPipeline(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $subject = new Subject($user, $user);

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        $pipeline = $this->pipeline();
        $capped   = $pipeline->capped(['posts:*'])->capped(['posts:read']);

        self::assertNotSame($pipeline, $capped);
        self::assertTrue($capped->decide($subject, 'posts:read', null, [])->isAllowed());
        self::assertSame(DecisionReason::SESSION_POLICY, $capped->decide($subject, 'posts:edit', null, [])->reason);
        self::assertTrue($pipeline->decide($subject, 'posts:edit', null, [])->isAllowed());
        self::assertTrue($pipeline->capped(['posts:*'])->decide($subject, 'posts:edit', null, [])->isAllowed());
    }

    /**
     * The session cap resolver caps each check by the credential's scopes, and
     * without one only the explicit caps count.
     *
     * @return void
     */
    public function testTheSessionCapResolverCapsEachCheck(): void
    {
        $machine = \Mockery::mock(AuthorizableIdentity::class, AuthorizableMachine::class);

        $machine->shouldReceive('getPermissions')->andReturn(['*']);
        $machine->shouldReceive('getPolicies')->andReturn([]);
        $machine->shouldReceive('isAuthorizationActive')->andReturn(true);

        $subject  = new Subject($machine, $machine);
        $source   = new StubSessionPolicySource(['posts:*']);
        $pipeline = new DecisionPipeline(new PolicyEvaluator, new DefaultPolicyResolver, sessionCaps: new SessionCapResolver($source));

        self::assertTrue($pipeline->decide($subject, 'posts:edit', null, [])->isAllowed());
        self::assertSame(DecisionReason::SESSION_POLICY, $pipeline->decide($subject, 'users:read', null, [])->reason);
        self::assertCount(2, $source->calls);
        self::assertSame(DecisionReason::SESSION_POLICY, (new DecisionPipeline(new PolicyEvaluator, new DefaultPolicyResolver))->decide($subject, 'posts:edit', null, [])->reason);
    }

    /**
     * A policy document that cannot be read denies as an invalid policy at the
     * deny stage, even when the subject holds the permission.
     *
     * @return void
     */
    public function testAnUnreadablePolicyIsAnInvalidPolicy(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        $policies = \Mockery::mock(PolicyResolver::class);
        $policies->shouldReceive('policiesFor')->once()->with($user)->andThrow(new InvalidPolicyDocumentException('broken', 'unreadable'));

        $decision = (new DecisionPipeline(new PolicyEvaluator, $policies))->decide(new Subject($user, $user), 'posts:read', null, []);

        self::assertSame(DecisionReason::INVALID_POLICY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
        self::assertSame([], $decision->trace);
    }

    /**
     * A guardrail caps every check but that of managing the guardrails, which
     * reads none and records its guardrail stage as exempt; without a guardrail
     * resolver no check is capped.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardrailsCapEveryCheckButManagingThem(): void
    {
        $user    = StubIdentity::create(['id' => 'guardrail-admin']);
        $subject = new Subject($user, $user);

        $user->givePermission(Permission::create(['name' => PackagePermissions::GUARDRAILS_MANAGE]));
        $user->givePermission(Permission::create(['name' => 'users:read']));

        $guardrails = GuardrailService::instance();

        self::assertInstanceOf(GuardrailService::class, $guardrails);

        $guardrails->set(self::stored('posts-only', [['effect' => 'allow', 'actions' => ['posts:*']]]), null, $user);

        $pipeline = $this->pipeline();
        $exempt   = $pipeline->decide($subject, PackagePermissions::GUARDRAILS_MANAGE, null, []);

        self::assertTrue($exempt->isAllowed());
        self::assertEquals(new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::EXEMPT), $exempt->trace[0]);
        self::assertSame(DecisionReason::GUARDRAIL, $pipeline->decide($subject, 'users:read', null, [])->reason);

        $unguarded = new DecisionPipeline(new PolicyEvaluator, new DefaultPolicyResolver);
        $read      = $unguarded->decide($subject, 'users:read', null, []);

        self::assertTrue($read->isAllowed());
        self::assertEquals(new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::UNCAPPED), $read->trace[0]);
        self::assertEquals(new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::EXEMPT), $unguarded->decide($subject, PackagePermissions::GUARDRAILS_MANAGE, null, [])->trace[0]);
    }

    /**
     * What the caller passes is read under `input` alone, with or without a
     * check context factory, and never as another namespace.
     *
     * @return void
     */
    public function testTheCallersValuesAreReadUnderInputAlone(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $subject = new Subject($user, $user);
        $policy  = EvaluationPolicy::fromArray(['name' => 'drafts', 'statements' => [
            ['effect' => 'allow', 'actions' => ['posts:edit'], 'conditions' => ['eq' => ['input.status' => 'draft']]],
            ['effect' => 'allow', 'actions' => ['posts:publish'], 'conditions' => ['eq' => ['request.ip' => '10.0.0.1']]],
        ]]);

        $factory = $this->app?->make(CheckContextFactory::class);

        self::assertInstanceOf(CheckContextFactory::class, $factory);

        $pipelines = [new DecisionPipeline(new PolicyEvaluator, new DefaultPolicyResolver), new DecisionPipeline(new PolicyEvaluator, new DefaultPolicyResolver, $factory)];

        foreach ($pipelines as $pipeline) {
            $pipeline = $pipeline->withPolicies([$policy]);

            self::assertTrue($pipeline->decide($subject, 'posts:edit', null, ['status' => 'draft'])->isAllowed());
            self::assertFalse($pipeline->decide($subject, 'posts:edit', null, ['status' => 'live'])->isAllowed());
            self::assertFalse($pipeline->decide($subject, 'posts:publish', null, ['request' => ['ip' => '10.0.0.1']])->isAllowed());
        }
    }

    /**
     * Return a pipeline with every source the service provider gives the
     * manager.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline
     */
    private function pipeline(): DecisionPipeline
    {
        return new DecisionPipeline(
            new PolicyEvaluator,
            new DefaultPolicyResolver,
            null,
            new ResourcePolicyResolver,
            new GuardrailResolver,
        );
    }

    /**
     * Return the resource policy service, as the container binds it.
     *
     * @return \SineMacula\Laravel\Authorization\Services\ResourcePolicyService
     */
    private static function resourcePolicies(): ResourcePolicyService
    {
        $service = ResourcePolicyService::instance();

        self::assertInstanceOf(ResourcePolicyService::class, $service);

        return $service;
    }

    /**
     * Create a stored policy of the statements.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function stored(string $name, array $statements): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => $statements]]);
    }

    /**
     * Return an override policy allowing the action.
     *
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function allowing(string $action): EvaluationPolicy
    {
        return EvaluationPolicy::fromArray(['name' => 'override', 'statements' => [['effect' => 'allow', 'actions' => [$action]]]]);
    }
}
