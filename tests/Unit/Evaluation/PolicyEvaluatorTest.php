<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;

/**
 * Unit tests for the policy evaluator's deny, allow and implicit stages.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 */
#[CoversClass(PolicyEvaluator::class)]
final class PolicyEvaluatorTest extends TestCase
{
    /**
     * With no policies nothing names the check, so it is denied as no_match at
     * the implicit stage, by no statement and with an empty trace.
     *
     * @return void
     */
    public function testNoPoliciesDeniesAsNoMatch(): void
    {
        $decision = (new PolicyEvaluator)->evaluate([], 'posts:create');

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionEffect::DENY, $decision->effect);
        self::assertSame(DecisionReason::NO_MATCH, $decision->reason);
        self::assertSame(DecisionStage::IMPLICIT, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertSame([], $decision->trace);
    }

    /**
     * A policy with no statements adds nothing to the trace and does not affect
     * the decision.
     *
     * @return void
     */
    public function testPolicyWithoutStatementsContributesNothing(): void
    {
        $decision = (new PolicyEvaluator)->evaluate([new Policy('empty', [])], 'posts:create');

        self::assertEquals(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT), $decision);
    }

    /**
     * An allow statement that matches allows the check at the allow stage, with
     * no reason, and names the statement that decided it.
     *
     * @return void
     */
    public function testMatchingAllowAllowsAtAllowStage(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:create');

        self::assertTrue($decision->isAllowed());
        self::assertSame(DecisionEffect::ALLOW, $decision->effect);
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertEquals([self::reference('p', 0)], $decision->statements);
        self::assertEquals([self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'p', 0)], $decision->trace);
    }

    /**
     * A deny statement that matches denies the check as explicit_deny at the
     * deny stage, and its trace entry belongs to the deny stage.
     *
     * @return void
     */
    public function testMatchingDenyDeniesExplicitly(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'deny-pol',
            'statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:delete');

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
        self::assertEquals([self::reference('deny-pol', 0)], $decision->statements);
        self::assertEquals([self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'deny-pol', 0)], $decision->trace);
    }

    /**
     * When an allow and a deny both match, the explicit deny wins, only the
     * deny is named as deciding it, and the allow is never assessed.
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

        self::assertEquals(Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [self::reference('p', 1)], [
            self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'p', 1),
        ]), $decision);
    }

    /**
     * A deny that decides ends the decision at the deny stage: the allow
     * statements are not assessed, so only the deny is traced (AUTHZ-7.1).
     *
     * @return void
     */
    public function testDecidingDenyStopsAllowsBeingAssessed(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [
                ['effect' => 'deny', 'actions' => ['posts:*']],
                ['effect' => 'allow', 'actions' => ['posts:*']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:create');

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertEquals([self::reference('p', 0)], $decision->statements);
        self::assertEquals([
            self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'p', 0),
        ], $decision->trace);
    }

    /**
     * Every matching deny is named as deciding the denial, across policies, in
     * the order they were assessed.
     *
     * @return void
     */
    public function testEveryMatchingDenyIsNamed(): void
    {
        $first = Policy::fromArray([
            'name'       => 'a',
            'statements' => [
                ['effect' => 'deny', 'actions' => ['posts:read']],
                ['effect' => 'deny', 'actions' => ['users:read']],
            ],
        ]);

        $second = Policy::fromArray([
            'name'       => 'b',
            'statements' => [['effect' => 'deny', 'actions' => ['posts:*']]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$first, $second], 'posts:read');

        self::assertEquals([self::reference('a', 0), self::reference('b', 0)], $decision->statements);
        self::assertEquals([
            self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'a', 0),
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'a', 1),
            self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'b', 0),
        ], $decision->trace);
    }

    /**
     * When no deny decides, every statement is traced, the deny stage first and
     * then the allow stage, each in order of position, and a statement that
     * does not name the check as not_applicable with no conditions.
     *
     * @return void
     */
    public function testEveryStatementIsTracedDenyStageFirst(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'named-policy',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['users:*']],
                ['effect' => 'allow', 'actions' => ['posts:create']],
                ['effect' => 'deny', 'actions' => ['posts:create'], 'conditions' => ['tenant' => 'org-1']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:create', null, ['tenant' => 'org-2']);

        self::assertTrue($decision->isAllowed());
        self::assertCount(3, $decision->trace);

        $expected = [
            [DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 2, ['tenant' => false]],
            [DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 0, []],
            [DecisionStage::ALLOW, TraceOutcome::MATCHED, 1, []],
        ];

        foreach ($expected as $position => [$stage, $outcome, $index, $conditions]) {
            $entry = $decision->trace[$position];

            self::assertSame($stage, $entry->stage);
            self::assertSame($outcome, $entry->outcome);
            self::assertNotNull($entry->statement);
            self::assertSame('named-policy', $entry->statement->policy);
            self::assertSame($index, $entry->statement->index);
            self::assertSame($conditions, $entry->conditions);
        }
    }

    /**
     * Policies are assessed in order of name, whatever order they are passed
     * in, and each policy's statements in order of position.
     *
     * @return void
     */
    public function testPoliciesAreAssessedInOrderOfName(): void
    {
        $zeta = Policy::fromArray([
            'name'       => 'zeta',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:read']],
                ['effect' => 'allow', 'actions' => ['users:read']],
            ],
        ]);

        $alpha = Policy::fromArray([
            'name'       => 'alpha',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$zeta, $alpha], 'posts:read');

        self::assertEquals([self::reference('alpha', 0), self::reference('zeta', 0)], $decision->statements);
        self::assertEquals([
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'alpha', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'zeta', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'zeta', 1),
        ], $decision->trace);
    }

    /**
     * Every order the policies can be passed in gives an identical decision:
     * the same effect, reason, stage, deciding statements and trace
     * (AUTHZ-7.9).
     *
     * @return void
     */
    public function testPolicyOrderDoesNotChangeTheDecision(): void
    {
        $policies = [
            Policy::fromArray([
                'name'       => 'reader',
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:read']],
                    ['effect' => 'allow', 'actions' => ['posts:update'], 'conditions' => ['owner' => true]],
                ],
            ]),
            Policy::fromArray([
                'name'       => 'blocker',
                'statements' => [
                    ['effect' => 'deny', 'actions' => ['posts:delete']],
                    ['effect' => 'deny', 'actions' => ['posts:*'], 'conditions' => ['banned' => true]],
                ],
            ]),
            Policy::fromArray([
                'name'       => 'editor',
                'statements' => [['effect' => 'allow', 'actions' => ['posts:*']]],
            ]),
            new Policy('broken', [
                new Statement(PolicyEffect::ALLOW, ['posts:archive'], ['*'], ['k' => ['bogus' => 1]]),
            ]),
        ];

        $checks = [
            ['posts:read', ['banned' => false, 'k' => 1]],
            ['posts:update', ['owner' => false, 'banned' => false]],
            ['posts:delete', ['banned' => false]],
            ['posts:read', ['banned' => true]],
            ['posts:archive', ['banned' => false, 'k' => 1]],
            ['users:read', []],
        ];

        $evaluator = new PolicyEvaluator;

        foreach ($checks as [$action, $context]) {
            $baseline = $evaluator->evaluate($policies, $action, null, $context);

            foreach (self::permutations($policies) as $order) {
                self::assertEquals($baseline, $evaluator->evaluate($order, $action, null, $context), $action);
            }
        }
    }

    /**
     * Policies that share a name, as a platform policy and a tenant policy may,
     * are assessed in order of their stored key after their name, whatever
     * order they are passed in and whatever their documents, and each reference
     * carries its policy's key.
     *
     * @return void
     */
    public function testPoliciesOfOneNameAreAssessedInOrderOfKey(): void
    {
        // The policy keyed b sorts first by its document, so only ordering by
        // key puts the policy keyed a first.
        $keyedB = Policy::fromArray([
            'name'       => 'shared',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:read']],
                ['effect' => 'allow', 'actions' => ['users:read']],
            ],
        ])->withId('b');

        $keyedA = Policy::fromArray([
            'name'       => 'shared',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]],
        ])->withId('a');

        $alpha = Policy::fromArray([
            'name'       => 'alpha',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]],
        ])->withId('z');

        $expected = Decision::allow(DecisionStage::ALLOW, [
            self::reference('alpha', 0, 'z'),
            self::reference('shared', 0, 'a'),
            self::reference('shared', 0, 'b'),
        ], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'alpha', 0, [], 'z'),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'shared', 0, [], 'a'),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'shared', 0, [], 'b'),
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'shared', 1, [], 'b'),
        ]);

        $evaluator = new PolicyEvaluator;

        self::assertEquals($expected, $evaluator->evaluate([$keyedB, $keyedA, $alpha], 'posts:read'));
        self::assertEquals($expected, $evaluator->evaluate([$alpha, $keyedA, $keyedB], 'posts:read'));
    }

    /**
     * Policies that share a name and have no stored key, as policies built in
     * code may, are assessed in order of their documents, so the order they are
     * passed in does not change the trace.
     *
     * @return void
     */
    public function testUnkeyedPoliciesOfOneNameAreAssessedInOrderOfDocument(): void
    {
        $single = Policy::fromArray([
            'name'       => 'shared',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]],
        ]);

        // This document sorts before the single-statement one, since its first
        // statement is followed by a comma rather than the end of the list.
        $double = Policy::fromArray([
            'name'       => 'shared',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:read']],
                ['effect' => 'allow', 'actions' => ['users:read']],
            ],
        ]);

        $expected = Decision::allow(DecisionStage::ALLOW, [
            self::reference('shared', 0),
            self::reference('shared', 0),
        ], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'shared', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'shared', 1),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'shared', 0),
        ]);

        $evaluator = new PolicyEvaluator;

        self::assertEquals($expected, $evaluator->evaluate([$single, $double], 'posts:read'));
        self::assertEquals($expected, $evaluator->evaluate([$double, $single], 'posts:read'));
    }

    /**
     * Every matching allow is named as deciding the allow; an allow whose
     * resource does not match is traced as not_applicable and not named.
     *
     * @return void
     */
    public function testEveryMatchingAllowIsNamed(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'multi-allow',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['first']],
                ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['second']],
                ['effect' => 'allow', 'actions' => ['posts:*']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', 'first');

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('multi-allow', 0), self::reference('multi-allow', 2)], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'multi-allow', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'multi-allow', 1),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'multi-allow', 2),
        ]), $decision);
    }

    /**
     * An allow that names the check but whose condition does not hold denies it
     * as condition_failed at the implicit stage, by no statement, and its trace
     * entry records the condition key as failed.
     *
     * @return void
     */
    public function testAllowWithFailedConditionDeniesAsConditionFailed(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'cond-pol',
            'statements' => [[
                'effect'     => 'allow',
                'actions'    => ['posts:create'],
                'conditions' => ['tenant' => ['eq' => 'org-1']],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:create', null, ['tenant' => 'org-2']);

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::CONDITION_FAILED, $decision->reason);
        self::assertSame(DecisionStage::IMPLICIT, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertEquals([
            self::entry(DecisionStage::ALLOW, TraceOutcome::CONDITION_FAILED, 'cond-pol', 0, ['tenant' => false]),
        ], $decision->trace);
    }

    /**
     * An allow whose conditions fail makes the denial condition_failed even
     * when other allows do not name the check at all.
     *
     * @return void
     */
    public function testConditionFailedTakesPrecedenceOverNoMatch(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['users:read']],
                ['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['tenant' => 'org-1']],
                ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['posts/1']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['tenant' => 'org-2']);

        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'p', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::CONDITION_FAILED, 'p', 1, ['tenant' => false]),
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'p', 2),
        ]), $decision);
    }

    /**
     * When no statement names the check, it is denied as no_match, every
     * statement traced as not_applicable, the deny stage first.
     *
     * @return void
     */
    public function testNoStatementNamingTheCheckDeniesAsNoMatch(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['users:read']],
                ['effect' => 'deny', 'actions' => ['users:delete']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read');

        self::assertEquals(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], [
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'p', 1),
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'p', 0),
        ]), $decision);
    }

    /**
     * A deny whose conditions definitely do not hold decides nothing: with no
     * allow, the check is denied as no_match rather than explicit_deny or
     * condition_failed.
     *
     * @return void
     */
    public function testDenyWithFailedConditionsDecidesNothing(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [[
                'effect'     => 'deny',
                'actions'    => ['posts:read'],
                'conditions' => ['tenant' => 'org-1'],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['tenant' => 'org-2']);

        self::assertEquals(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], [
            self::entry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 'p', 0, ['tenant' => false]),
        ]), $decision);
    }

    /**
     * A deny whose condition key is missing from the context applies: the
     * evaluator fails closed on an undecidable deny, over a matching allow,
     * which is never assessed.
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

        self::assertEquals(Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [self::reference('deny-missing', 1)], [
            self::entry(DecisionStage::DENY, TraceOutcome::UNDECIDABLE, 'deny-missing', 1, ['x' => false]),
        ]), $decision);
    }

    /**
     * An allow whose condition key is missing from the context does not apply,
     * so the check is denied as condition_failed.
     *
     * @return void
     */
    public function testAllowWithMissingConditionKeyDeniesAsConditionFailed(): void
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

        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, 'allow-missing', 0, ['x' => false]),
        ]), $decision);
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

        self::assertEquals(Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [self::reference('deny-unresolved', 0)], [
            self::entry(DecisionStage::DENY, TraceOutcome::UNDECIDABLE, 'deny-unresolved', 0),
        ]), $decision);
    }

    /**
     * An allow whose resource pattern references a value that cannot be
     * resolved does not apply, so the check is denied as condition_failed.
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

        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, 'allow-unresolved', 0),
        ]), $decision);
    }

    /**
     * A deny whose interpolated operand substitutes a value of the wrong type
     * cannot be decided, so it applies rather than denying the check as an
     * invalid policy, and the allow after it is never assessed.
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

        self::assertEquals(Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [self::reference('deny-substituted', 0)], [
            self::entry(DecisionStage::DENY, TraceOutcome::UNDECIDABLE, 'deny-substituted', 0, ['n' => false]),
        ]), $decision);
    }

    /**
     * An allow whose interpolated operand substitutes a value of the wrong type
     * cannot be decided, so it does not apply, and the check is denied as
     * condition_failed rather than as an invalid policy.
     *
     * @return void
     */
    public function testAllowWithWrongTypedInterpolatedOperandDoesNotApply(): void
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

        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, 'allow-substituted', 0, ['n' => false]),
        ]), $decision);
    }

    /**
     * A check without a resource does not match an allow scoped to particular
     * resources, so the statement is not_applicable and the check is denied as
     * no_match.
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

        self::assertEquals(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'scoped', 0),
        ]), $decision);
    }

    /**
     * An invalid allow statement denies the check as an invalid policy at the
     * allow stage, over a matching allow, naming the invalid statement; every
     * statement of every policy is still assessed and traced, the deny stage
     * first.
     *
     * @return void
     */
    public function testInvalidAllowStatementDeniesAsInvalidPolicyOverAllow(): void
    {
        $first = Policy::fromArray([
            'name'       => 'first',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]],
        ]);

        $broken = new Policy('broken', [
            new Statement(PolicyEffect::ALLOW, ['posts:read'], ['*'], ['k' => ['bogus' => 1]]),
            new Statement(PolicyEffect::ALLOW, ['posts:read']),
        ]);

        $last = Policy::fromArray([
            'name'       => 'last',
            'statements' => [['effect' => 'deny', 'actions' => ['users:read']]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$first, $broken, $last], 'posts:read', null, ['k' => 1]);

        self::assertEquals(Decision::deny(DecisionReason::INVALID_POLICY, DecisionStage::ALLOW, [self::reference('broken', 0)], [
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'last', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::INVALID, 'broken', 0, ['k' => false]),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'broken', 1),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'first', 0),
        ]), $decision);
    }

    /**
     * An invalid deny statement denies the check as an invalid policy at the
     * deny stage, its trace entry in the deny stage, over a matching allow that
     * is never assessed.
     *
     * @return void
     */
    public function testInvalidDenyStatementDeniesAsInvalidPolicy(): void
    {
        $policy = new Policy('broken', [
            new Statement(PolicyEffect::ALLOW, ['posts:read']),
            new Statement(PolicyEffect::DENY, ['posts:read'], ['*'], ['k' => ['bogus' => 1]]),
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['k' => 1]);

        self::assertEquals(Decision::deny(DecisionReason::INVALID_POLICY, DecisionStage::DENY, [self::reference('broken', 1)], [
            self::entry(DecisionStage::DENY, TraceOutcome::INVALID, 'broken', 1, ['k' => false]),
        ]), $decision);
    }

    /**
     * An explicit deny wins over an invalid deny statement: the denial is
     * explicit_deny, naming only the denies that apply, with the invalid
     * statement still traced and the allow never assessed.
     *
     * @return void
     */
    public function testExplicitDenyOverridesInvalidStatement(): void
    {
        $first = Policy::fromArray([
            'name'       => 'first',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]],
        ]);

        $broken = new Policy('broken', [
            new Statement(PolicyEffect::DENY, ['posts:read'], ['*'], ['k' => ['bogus' => 1]]),
            new Statement(PolicyEffect::DENY, ['posts:read']),
        ]);

        $last = Policy::fromArray([
            'name'       => 'last',
            'statements' => [['effect' => 'deny', 'actions' => ['posts:read']]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$first, $broken, $last], 'posts:read', null, ['k' => 1]);

        self::assertEquals(Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [self::reference('broken', 1), self::reference('last', 0)], [
            self::entry(DecisionStage::DENY, TraceOutcome::INVALID, 'broken', 0, ['k' => false]),
            self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'broken', 1),
            self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'last', 0),
        ]), $decision);
    }

    /**
     * An invalid statement whose action does not match the check is never
     * assessed, so it is not_applicable like any other statement that does not
     * name the check, and the allow decides.
     *
     * @return void
     */
    public function testInvalidStatementWithNonMatchingActionIsNotApplicable(): void
    {
        $policy = new Policy('broken', [
            new Statement(PolicyEffect::DENY, ['users:*'], ['*'], ['k' => ['bogus' => 1]]),
            new Statement(PolicyEffect::ALLOW, ['posts:read']),
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['k' => 1]);

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('broken', 1)], [
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'broken', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'broken', 1),
        ]), $decision);
    }

    /**
     * A deny with a definitely-false condition is condition_failed and decides
     * nothing even when another of its conditions cannot be decided, whichever
     * order they appear in; each key is traced in the statement's order.
     *
     * @return void
     */
    public function testDenyWithFalseConditionDecidesNothingDespiteUndecidableCondition(): void
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

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('deny-mixed', 2)], [
            self::entry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 'deny-mixed', 0, ['missing' => false, 'tenant' => false]),
            self::entry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 'deny-mixed', 1, ['tenant' => false, 'missing' => false]),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'deny-mixed', 2),
        ]), $decision);
        self::assertSame(['missing', 'tenant'], \array_keys($decision->trace[0]->conditions));
        self::assertSame(['tenant', 'missing'], \array_keys($decision->trace[1]->conditions));
    }

    /**
     * A deny scoped to an IPv6 range applies to an address within it, its
     * condition traced as held and the allow never assessed, and decides
     * nothing for one outside it.
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

        self::assertEquals(Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [self::reference('deny-ipv6', 0)], [
            self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'deny-ipv6', 0, ['ip' => true]),
        ]), $inside);

        $outside = $evaluator->evaluate([$policy], 'posts:read', null, ['ip' => '2001:db9::1']);

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('deny-ipv6', 1)], [
            self::entry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 'deny-ipv6', 0, ['ip' => false]),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'deny-ipv6', 1),
        ]), $outside);
    }

    /**
     * The condition keys a statement tested reach the trace with a boolean for
     * each, never the context values they were tested against.
     *
     * @return void
     */
    public function testTraceRecordsConditionKeysAsBooleans(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [[
                'effect'     => 'allow',
                'actions'    => ['posts:read'],
                'conditions' => ['tenant' => 'org-1', 'role' => ['in' => ['admin']]],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['tenant' => 'org-1', 'role' => 'guest']);

        self::assertSame(['tenant' => true, 'role' => false], $decision->trace[0]->conditions);
        self::assertSame(TraceOutcome::CONDITION_FAILED, $decision->trace[0]->outcome);
    }

    /**
     * A policy's statement references and the trace entries of statements that
     * do not name the action are built once and shared by the evaluator's every
     * decision over that policy, while a statement that names it is assessed
     * afresh.
     *
     * @return void
     */
    public function testPolicyStatementEntriesAreBuiltOnce(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [
                ['effect' => 'deny', 'actions' => ['posts:delete']],
                ['effect' => 'allow', 'actions' => ['posts:read']],
            ],
        ]);

        $evaluator = new PolicyEvaluator;
        $first     = $evaluator->evaluate([$policy], 'posts:read');
        $second    = $evaluator->evaluate([$policy], 'posts:read');

        self::assertSame($first->trace[0], $second->trace[0]);
        self::assertSame($first->statements[0], $second->statements[0]);
        self::assertNotSame($first->trace[1], $second->trace[1]);
        self::assertEquals(self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'p', 0), $first->trace[0]);
    }

    /**
     * Return a reference to the statement at the index of the named policy,
     * carrying the policy's stored key when it has one.
     *
     * @param  string  $policy
     * @param  int  $index
     * @param  string|null  $policyId
     * @return \SineMacula\Laravel\Authorization\Evaluation\StatementReference
     */
    private static function reference(string $policy, int $index, ?string $policyId = null): StatementReference
    {
        return new StatementReference($policy, $index, $policyId);
    }

    /**
     * Return the trace entry expected for the statement at the index of the
     * named policy.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome  $outcome
     * @param  string  $policy
     * @param  int  $index
     * @param  array<string, bool>  $conditions
     * @param  string|null  $policyId
     * @return \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
     */
    private static function entry(DecisionStage $stage, TraceOutcome $outcome, string $policy, int $index, array $conditions = [], ?string $policyId = null): TraceEntry
    {
        return new TraceEntry($stage, $outcome, self::reference($policy, $index, $policyId), $conditions);
    }

    /**
     * Return every ordering of the policies.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return list<list<\SineMacula\Laravel\Authorization\Evaluation\Policy>>
     */
    private static function permutations(array $policies): array
    {
        if (\count($policies) <= 1) {
            return [$policies];
        }

        $orders = [];

        foreach ($policies as $position => $policy) {
            $rest = $policies;

            unset($rest[$position]);

            foreach (self::permutations(\array_values($rest)) as $order) {
                $orders[] = [$policy, ...$order];
            }
        }

        return $orders;
    }
}
