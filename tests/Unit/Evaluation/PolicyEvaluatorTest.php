<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceDecision;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * Unit tests for the four IAM evaluation branches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PolicyEvaluator::class)]
final class PolicyEvaluatorTest extends TestCase
{
    /**
     * No policies / no match -> implicit deny.
     *
     * @return void
     */
    public function testImplicitDenyWhenNoPolicies(): void
    {
        $decision = (new PolicyEvaluator)->evaluate([], 'posts:create');

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::IMPLICIT_DENY, $decision->reason);
        self::assertSame([], $decision->trace);
    }

    /**
     * Only allow matches -> explicit allow.
     *
     * @return void
     */
    public function testExplicitAllow(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:create');

        self::assertTrue($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, $decision->reason);
        self::assertNotNull($decision->matchedStatement);
        self::assertCount(1, $decision->trace);
        self::assertSame(TraceDecision::MATCHED, $decision->trace[0]['decision']);
    }

    /**
     * Only deny matches -> explicit deny.
     *
     * @return void
     */
    public function testExplicitDeny(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [['effect' => 'deny', 'actions' => ['posts:create']]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:create');

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
    }

    /**
     * Allow + deny -> explicit deny wins.
     *
     * @return void
     */
    public function testExplicitDenyOverridesAllow(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:create']],
                ['effect' => 'deny', 'actions' => ['posts:create']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:create');

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
    }

    /**
     * Statements that do not match are traced as skipped with a reason.
     *
     * @return void
     */
    public function testTraceCapturesSkippedStatements(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'named-policy',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['users:*']],
                ['effect' => 'allow', 'actions' => ['posts:create']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:create');

        self::assertTrue($decision->allowed);
        self::assertCount(2, $decision->trace);

        self::assertSame([
            'policy'          => 'named-policy',
            'statement_index' => 0,
            'decision'        => TraceDecision::SKIPPED,
            'reason'          => 'action/resource did not match',
        ], $decision->trace[0]);

        self::assertSame([
            'policy'          => 'named-policy',
            'statement_index' => 1,
            'decision'        => TraceDecision::MATCHED,
            'reason'          => 'explicit allow',
        ], $decision->trace[1]);
    }

    /**
     * Trace entry for an explicit deny carries the deny reason verbatim.
     *
     * @return void
     */
    public function testTraceCapturesExplicitDenyEntry(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'deny-pol',
            'statements' => [
                ['effect' => 'deny', 'actions' => ['posts:delete']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:delete');

        self::assertSame([
            'policy'          => 'deny-pol',
            'statement_index' => 0,
            'decision'        => TraceDecision::MATCHED,
            'reason'          => 'explicit deny',
        ], $decision->trace[0]);
    }

    /**
     * The first matched allow is preserved across subsequent matches (kills the
     * AssignCoalesce mutation).
     *
     * @return void
     */
    public function testFirstAllowIsPreservedWhenMultipleMatch(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'multi-allow',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['first']],
                ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['second']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', 'first');

        self::assertNotNull($decision->matchedStatement);
        // Both statements would match action; only the first matches resource,
        // so it must be the matched statement.
        self::assertSame(['first'], $decision->matchedStatement->resources);
    }

    /**
     * The trace for a condition-skipped statement records the reason.
     *
     * @return void
     */
    public function testTraceConditionSkipReasonIsLiteral(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'cond-pol',
            'statements' => [[
                'effect'     => 'allow',
                'actions'    => ['x'],
                'conditions' => ['t' => ['eq' => 'a']],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'x', null, ['t' => 'b']);

        self::assertSame([
            'policy'          => 'cond-pol',
            'statement_index' => 0,
            'decision'        => TraceDecision::SKIPPED,
            'reason'          => 'conditions not satisfied',
        ], $decision->trace[0]);
    }

    /**
     * Condition mismatch skips the statement.
     *
     * @return void
     */
    public function testConditionMismatchSkips(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [
                [
                    'effect'     => 'allow',
                    'actions'    => ['posts:create'],
                    'conditions' => ['tenant' => ['eq' => 'org-1']],
                ],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:create', null, ['tenant' => 'org-2']);

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::IMPLICIT_DENY, $decision->reason);
        self::assertSame(TraceDecision::SKIPPED, $decision->trace[0]['decision']);
        self::assertStringContainsString('conditions', $decision->trace[0]['reason']);
    }

    /**
     * Deny short-circuits subsequent allows.
     *
     * @return void
     */
    public function testDenyShortCircuits(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [
                ['effect' => 'deny', 'actions' => ['posts:*']],
                ['effect' => 'allow', 'actions' => ['posts:*']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:create');

        self::assertFalse($decision->allowed);
        self::assertCount(1, $decision->trace);
    }

    /**
     * A deny whose condition key is missing from the context applies: the
     * evaluator fails closed on an undecidable deny.
     *
     * @return void
     */
    public function testDenyWithMissingConditionKeyApplies(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'deny-missing',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:read']],
                [
                    'effect'     => 'deny',
                    'actions'    => ['posts:read'],
                    'conditions' => ['x' => ['eq' => 'blocked']],
                ],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read');

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame($policy->statements[1], $decision->matchedStatement);
        self::assertCount(2, $decision->trace);
        self::assertSame([
            'policy'          => 'deny-missing',
            'statement_index' => 1,
            'decision'        => TraceDecision::MATCHED,
            'reason'          => 'explicit deny: key \'x\' is missing from the context',
        ], $decision->trace[1]);
    }

    /**
     * An allow whose condition key is missing from the context is skipped, so
     * the check falls through to an implicit deny.
     *
     * @return void
     */
    public function testAllowWithMissingConditionKeyIsSkipped(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'allow-missing',
            'statements' => [[
                'effect'     => 'allow',
                'actions'    => ['posts:read'],
                'conditions' => ['x' => ['eq' => 'yes']],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['y' => 'yes']);

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::IMPLICIT_DENY, $decision->reason);
        self::assertNull($decision->matchedStatement);
        self::assertSame([[
            'policy'          => 'allow-missing',
            'statement_index' => 0,
            'decision'        => TraceDecision::SKIPPED,
            'reason'          => 'could not be decided: key \'x\' is missing from the context',
        ]], $decision->trace);
    }

    /**
     * A deny whose resource pattern references a value that cannot be resolved
     * applies.
     *
     * @return void
     */
    public function testDenyWithUnresolvedResourcePatternApplies(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'deny-unresolved',
            'statements' => [[
                'effect'    => 'deny',
                'actions'   => ['posts:read'],
                'resources' => ['tenants/${context.tenant}/*'],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', 'tenants/org-1/posts');

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame($policy->statements[0], $decision->matchedStatement);
        self::assertSame([[
            'policy'          => 'deny-unresolved',
            'statement_index' => 0,
            'decision'        => TraceDecision::MATCHED,
            'reason'          => 'explicit deny: a resource pattern references a value that cannot be resolved',
        ]], $decision->trace);
    }

    /**
     * An allow whose resource pattern references a value that cannot be
     * resolved does not apply.
     *
     * @return void
     */
    public function testAllowWithUnresolvedResourcePatternDoesNotApply(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'allow-unresolved',
            'statements' => [[
                'effect'    => 'allow',
                'actions'   => ['posts:read'],
                'resources' => ['tenants/${context.tenant}/*'],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', 'tenants/org-1/posts');

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::IMPLICIT_DENY, $decision->reason);
        self::assertNull($decision->matchedStatement);
        self::assertSame([[
            'policy'          => 'allow-unresolved',
            'statement_index' => 0,
            'decision'        => TraceDecision::SKIPPED,
            'reason'          => 'could not be decided: a resource pattern references a value that cannot be resolved',
        ]], $decision->trace);
    }

    /**
     * A deny whose interpolated operand substitutes a value of the wrong type
     * cannot be decided, so it applies rather than denying the check as an
     * invalid policy.
     *
     * @return void
     */
    public function testDenyWithWrongTypedInterpolatedOperandApplies(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'deny-substituted',
            'statements' => [
                [
                    'effect'     => 'deny',
                    'actions'    => ['posts:read'],
                    'conditions' => ['n' => ['gt' => '${context.limit}']],
                ],
                ['effect' => 'allow', 'actions' => ['posts:read']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['n' => 5, 'limit' => 'abc']);

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame($policy->statements[0], $decision->matchedStatement);
        self::assertSame([[
            'policy'          => 'deny-substituted',
            'statement_index' => 0,
            'decision'        => TraceDecision::MATCHED,
            'reason'          => 'explicit deny: condition \'n\': the substituted operand is an invalid operand for operator \'gt\'',
        ]], $decision->trace);
    }

    /**
     * An allow whose interpolated operand substitutes a value of the wrong type
     * cannot be decided, so it is skipped rather than denying the check as an
     * invalid policy.
     *
     * @return void
     */
    public function testAllowWithWrongTypedInterpolatedOperandIsSkipped(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'allow-substituted',
            'statements' => [[
                'effect'     => 'allow',
                'actions'    => ['posts:read'],
                'conditions' => ['n' => ['gt' => '${context.limit}']],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['n' => 5, 'limit' => 'abc']);

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::IMPLICIT_DENY, $decision->reason);
        self::assertNull($decision->matchedStatement);
        self::assertSame([[
            'policy'          => 'allow-substituted',
            'statement_index' => 0,
            'decision'        => TraceDecision::SKIPPED,
            'reason'          => 'could not be decided: condition \'n\': the substituted operand is an invalid operand for operator \'gt\'',
        ]], $decision->trace);
    }

    /**
     * A check without a resource does not match an allow scoped to particular
     * resources.
     *
     * @return void
     */
    public function testResourceLessCheckDoesNotMatchResourceScopedAllow(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'scoped',
            'statements' => [[
                'effect'    => 'allow',
                'actions'   => ['posts:read'],
                'resources' => ['posts/1'],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read');

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::IMPLICIT_DENY, $decision->reason);
        self::assertSame([[
            'policy'          => 'scoped',
            'statement_index' => 0,
            'decision'        => TraceDecision::SKIPPED,
            'reason'          => 'action/resource did not match',
        ]], $decision->trace);
    }

    /**
     * An invalid statement denies the check as an invalid policy, keeps the
     * trace up to and including it, and short-circuits every later statement
     * and policy.
     *
     * @return void
     */
    public function testInvalidStatementReturnsInvalidPolicyAndShortCircuits(): void
    {
        $first = Policy::fromArray([
            'name'       => 'first',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]],
        ]);

        $broken = new Policy('broken', [
            new Statement(PolicyEffect::ALLOW, ['posts:read'], ['*'], ['k' => ['bogus' => 1]]),
            new Statement(PolicyEffect::DENY, ['posts:read']),
        ]);

        $last = Policy::fromArray([
            'name'       => 'last',
            'statements' => [['effect' => 'deny', 'actions' => ['posts:read']]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$first, $broken, $last], 'posts:read', null, ['k' => 1]);

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::INVALID_POLICY, $decision->reason);
        self::assertNull($decision->matchedStatement);
        self::assertSame([
            [
                'policy'          => 'first',
                'statement_index' => 0,
                'decision'        => TraceDecision::MATCHED,
                'reason'          => 'explicit allow',
            ],
            [
                'policy'          => 'broken',
                'statement_index' => 0,
                'decision'        => TraceDecision::MATCHED,
                'reason'          => 'invalid statement: condition \'k\' has an unknown operator \'bogus\'',
            ],
        ], $decision->trace);
    }

    /**
     * An invalid statement whose action does not match the check is never
     * assessed, so it is skipped like any other non-matching statement.
     *
     * @return void
     */
    public function testInvalidStatementWithNonMatchingActionIsSkipped(): void
    {
        $policy = new Policy('broken', [
            new Statement(PolicyEffect::DENY, ['users:*'], ['*'], ['k' => ['bogus' => 1]]),
            new Statement(PolicyEffect::ALLOW, ['posts:read']),
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['k' => 1]);

        self::assertTrue($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, $decision->reason);
        self::assertSame($policy->statements[1], $decision->matchedStatement);
        self::assertSame([
            [
                'policy'          => 'broken',
                'statement_index' => 0,
                'decision'        => TraceDecision::SKIPPED,
                'reason'          => 'action/resource did not match',
            ],
            [
                'policy'          => 'broken',
                'statement_index' => 1,
                'decision'        => TraceDecision::MATCHED,
                'reason'          => 'explicit allow',
            ],
        ], $decision->trace);
    }

    /**
     * A deny with a definitely-false condition is skipped even when another of
     * its conditions cannot be decided, whichever order they appear in.
     *
     * @return void
     */
    public function testDenyWithFalseConditionIsSkippedDespiteUndecidableCondition(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'deny-mixed',
            'statements' => [
                [
                    'effect'     => 'deny',
                    'actions'    => ['posts:read'],
                    'conditions' => [
                        'missing' => ['eq' => 'a'],
                        'tenant'  => ['eq' => 'org-1'],
                    ],
                ],
                [
                    'effect'     => 'deny',
                    'actions'    => ['posts:read'],
                    'conditions' => [
                        'tenant'  => ['eq' => 'org-1'],
                        'missing' => ['eq' => 'a'],
                    ],
                ],
                ['effect' => 'allow', 'actions' => ['posts:read']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['tenant' => 'org-2']);

        self::assertTrue($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, $decision->reason);
        self::assertSame($policy->statements[2], $decision->matchedStatement);
        self::assertSame([
            [
                'policy'          => 'deny-mixed',
                'statement_index' => 0,
                'decision'        => TraceDecision::SKIPPED,
                'reason'          => 'conditions not satisfied',
            ],
            [
                'policy'          => 'deny-mixed',
                'statement_index' => 1,
                'decision'        => TraceDecision::SKIPPED,
                'reason'          => 'conditions not satisfied',
            ],
            [
                'policy'          => 'deny-mixed',
                'statement_index' => 2,
                'decision'        => TraceDecision::MATCHED,
                'reason'          => 'explicit allow',
            ],
        ], $decision->trace);
    }

    /**
     * A deny scoped to an IPv6 range applies to an address within it and not to
     * one outside it.
     *
     * @return void
     */
    public function testIpv6CidrDenyApplies(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'deny-ipv6',
            'statements' => [
                [
                    'effect'     => 'deny',
                    'actions'    => ['posts:read'],
                    'conditions' => ['ip' => ['cidr' => '2001:db8::/32']],
                ],
                ['effect' => 'allow', 'actions' => ['posts:read']],
            ],
        ]);

        $evaluator = new PolicyEvaluator;

        $inside = $evaluator->evaluate([$policy], 'posts:read', null, ['ip' => '2001:db8::1']);

        self::assertFalse($inside->allowed);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $inside->reason);
        self::assertSame($policy->statements[0], $inside->matchedStatement);
        self::assertSame([[
            'policy'          => 'deny-ipv6',
            'statement_index' => 0,
            'decision'        => TraceDecision::MATCHED,
            'reason'          => 'explicit deny',
        ]], $inside->trace);

        $outside = $evaluator->evaluate([$policy], 'posts:read', null, ['ip' => '2001:db9::1']);

        self::assertTrue($outside->allowed);
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, $outside->reason);
        self::assertSame(TraceDecision::SKIPPED, $outside->trace[0]['decision']);
        self::assertSame('conditions not satisfied', $outside->trace[0]['reason']);
    }
}
