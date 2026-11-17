<?php

declare(strict_types = 1);

namespace Tests\Feature\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Evaluation\BreakGlassAttribution;
use SineMacula\Laravel\Authorization\Evaluation\CheckGrants;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionEvidence;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder;
use SineMacula\Laravel\Authorization\Evaluation\GrantProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Usage\WeighedGrants;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Feature\Stubs\StubGrantee;
use Tests\Feature\Stubs\StubSecondGrantee;
use Tests\TestCase;

/**
 * Feature tests for gathering the policies and the permission held a check
 * weighs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckGrants::class)]
final class CheckGrantsTest extends TestCase
{
    use ActivatesBreakGlass;

    /**
     * The policies come from the resolver, then the identity, then the
     * resource, and none from the resource without a resource policy resolver.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePoliciesComeFromTheResolverTheIdentityAndTheResource(): void
    {
        [$principal, $identity] = self::withPolicies();

        $subject = new Subject($principal, $identity);
        $post    = ResourceReference::record('posts', '7');
        $grants  = new CheckGrants(new DefaultPolicyResolver, new ResourcePolicyResolver);

        self::assertSame(['editing', 'no-publishing', 'locked'], self::names($grants->policies($subject, $post, null, null)));
        self::assertSame(['editing', 'no-publishing'], self::names((new CheckGrants(new DefaultPolicyResolver, null))->policies($subject, $post, null, null)));
    }

    /**
     * An explained check gathers the same policies, noting where the subject's
     * and its identity's came from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExplainedCheckNotesWhereThePoliciesCameFrom(): void
    {
        [$principal, $identity, [$editing, $identityPolicy]] = self::withPolicies();

        $post     = ResourceReference::record('posts', '7');
        $recorder = new EvidenceRecorder;
        $policies = (new CheckGrants(new DefaultPolicyResolver, new ResourcePolicyResolver))->policies(new Subject($principal, $identity), $post, $recorder, null);
        $allowed  = Decision::allow(DecisionStage::ALLOW, [new StatementReference('editing', 0, $editing->id), new StatementReference('no-publishing', 0, $identityPolicy->id)]);

        self::assertSame(['editing', 'no-publishing', 'locked'], self::names($policies));
        self::assertEquals([
            new GrantProvenance(GrantSource::POLICY, "editing[{$editing->id}]", Reference::of($principal), false, [], true),
            new GrantProvenance(GrantSource::POLICY, "no-publishing[{$identityPolicy->id}]", Reference::of($identity), true, [], true),
        ], $recorder->evidenceFor($allowed)->grants);
    }

    /**
     * A resolver bound in place of the default cannot say where its policies
     * came from, so they are noted as unavailable, with the principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACustomResolversPoliciesAreUnavailable(): void
    {
        $user     = StubGrantee::create(['id' => 'user-1']);
        $subject  = new Subject($user, $user);
        $policy   = EvaluationPolicy::fromArray(['name' => 'coded', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]);
        $resolver = new class ($policy) implements PolicyResolver {
            /**
             * Create a resolver giving the policy to everyone.
             *
             * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
             */
            public function __construct(

                /** The policy given. */
                private readonly EvaluationPolicy $policy,
            ) {}

            /**
             * Return the policy.
             *
             * @param  object  $principal
             * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
             */
            #[\Override]
            public function policiesFor(object $principal): array
            {
                return [$this->policy];
            }
        };

        $recorder = new EvidenceRecorder;
        $policies = (new CheckGrants($resolver, null))->policies($subject, null, $recorder, null);

        $allowed = Decision::allow(DecisionStage::ALLOW, [new StatementReference('coded', 0)]);

        self::assertSame([$policy], $policies);
        self::assertEquals([GrantProvenance::unavailable('coded', Reference::of($user))], $recorder->evidenceFor($allowed)->grants);
    }

    /**
     * The permission held is asked for when the allow stage calls for it, and
     * noted, with the grantee holding it, on what a tracked check weighed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePermissionHeldIsNotedOnWhatWasWeighed(): void
    {
        $user    = StubGrantee::create(['id' => 'user-1']);
        $subject = new Subject($user, $user);
        $weighed = new WeighedGrants(true, true);

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        self::assertSame('posts:read', CheckGrants::permission($subject, 'posts:read', null, $weighed, null)());
        self::assertSame($user, $weighed->granteeOf('posts:read'));
        self::assertNull(CheckGrants::permission($subject, 'posts:delete', null, null, null)());
    }

    /**
     * An explained check notes where the permission held came from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExplainedCheckNotesWhereThePermissionCameFrom(): void
    {
        $user     = StubGrantee::create(['id' => 'user-1']);
        $subject  = new Subject($user, $user);
        $recorder = new EvidenceRecorder;
        $weighed  = new WeighedGrants(true, true);

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        self::assertSame('posts:read', CheckGrants::permission($subject, 'posts:read', $recorder, $weighed, null)());
        self::assertNull($weighed->granteeOf('posts:read'));
        self::assertEquals(
            new DecisionEvidence([new GrantProvenance(GrantSource::PERMISSION, 'posts:read', Reference::of($user), false, [], true)]),
            $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW)),
        );
    }

    /**
     * While the principal's break-glass activations count, the activations
     * behind its permissions and policies are noted as each resolves.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheActivationsBehindTheGrantsAreNoted(): void
    {
        $user    = StubGrantee::create(['id' => 'user-1']);
        $subject = new Subject($user, $user);
        $role    = self::emergencyRole();
        $policy  = Policy::create(['name' => 'deleting', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:delete']]]]]);

        $role->attachPolicy($policy);

        $activation = self::activate($user, $role);
        $create     = BreakGlassAttribution::of($subject, 'posts:create');
        $delete     = BreakGlassAttribution::of($subject, 'posts:delete');

        self::assertNotNull($create);
        self::assertNotNull($delete);
        self::assertSame('posts:create', CheckGrants::permission($subject, 'posts:create', null, null, $create)());
        $held = Decision::allow(DecisionStage::ALLOW, [], [new TraceEntry(DecisionStage::ALLOW, TraceOutcome::SATISFIED, permission: 'posts:create')]);

        self::assertSame([$activation->id], $create->behind($held, []));

        $policies = (new CheckGrants(new DefaultPolicyResolver, null))->policies($subject, null, null, $delete);
        $stated   = Decision::allow(DecisionStage::ALLOW, [new StatementReference('deleting', 0, $policy->id)]);

        self::assertSame([$activation->id], $delete->behind($stated, $policies));
    }

    /**
     * Return a principal and an identity that each have a policy, with those
     * policies, and attach a policy to the record `posts:7`.
     *
     * @return array{\Tests\Feature\Stubs\StubGrantee, \Tests\Feature\Stubs\StubSecondGrantee, list<\SineMacula\Laravel\Authorization\Models\Policy>}
     */
    private static function withPolicies(): array
    {
        $principal = StubGrantee::create(['id' => 'account-1']);
        $identity  = StubSecondGrantee::create(['id' => 'person-1']);
        $editing   = Policy::create(['name' => 'editing', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:*']]]]]);
        $denying   = Policy::create(['name' => 'no-publishing', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:publish']]]]]);
        $locked    = Policy::create(['name' => 'locked', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:edit']]]]]);

        $principal->attachPolicy($editing);
        $identity->attachPolicy($denying);

        $service = ResourcePolicyService::instance();

        self::assertInstanceOf(ResourcePolicyService::class, $service);

        $service->attach($locked, ['posts', 7]);

        return [$principal, $identity, [$editing, $denying]];
    }

    /**
     * Return the names of the policies, in order.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return list<string>
     */
    private static function names(array $policies): array
    {
        return \array_values(\array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $policies));
    }
}
