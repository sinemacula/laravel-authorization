<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
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
                ['effect' => 'deny', 'actions' => ['posts:create'], 'conditions' => ['eq' => ['input.tenant' => 'org-1']]],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:create', null, ['input' => ['tenant' => 'org-2']]);

        self::assertTrue($decision->isAllowed());
        self::assertCount(3, $decision->trace);

        $expected = [
            [DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 2, ['input.tenant' => false]],
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
                    ['effect' => 'allow', 'actions' => ['posts:update'], 'conditions' => ['eq' => ['input.owner' => true]]],
                ],
            ]),
            Policy::fromArray([
                'name'       => 'blocker',
                'statements' => [
                    ['effect' => 'deny', 'actions' => ['posts:delete']],
                    ['effect' => 'deny', 'actions' => ['posts:*'], 'conditions' => ['eq' => ['input.banned' => true]]],
                ],
            ]),
            Policy::fromArray([
                'name'       => 'editor',
                'statements' => [['effect' => 'allow', 'actions' => ['posts:*']]],
            ]),
            new Policy('broken', [
                new Statement(PolicyEffect::ALLOW, ['posts:archive'], ['*'], ['eq' => ['input.k' => [1]]]),
            ]),
        ];

        $checks = [
            ['posts:read', ['input' => ['banned' => false, 'k' => 1]]],
            ['posts:update', ['input' => ['owner' => false, 'banned' => false]]],
            ['posts:delete', ['input' => ['banned' => false]]],
            ['posts:read', ['input' => ['banned' => true]]],
            ['posts:archive', ['input' => ['banned' => false, 'k' => 1]]],
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
     * A check on a type alone is allowed only by an allow that covers every
     * record of the type: an allow on `post:?`, which needs an id character, is
     * traced as not_applicable and not named, and the one on `post:*` is.
     *
     * @return void
     */
    public function testATypeAloneIsAllowedOnlyByAnAllowCoveringEveryRecord(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'type-allow',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['post:?']],
                ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['post:*']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', 'post:*');

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('type-allow', 1)], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'type-allow', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'type-allow', 1),
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
                'conditions' => ['eq' => ['input.tenant' => 'org-1']],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:create', null, ['input' => ['tenant' => 'org-2']]);

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::CONDITION_FAILED, $decision->reason);
        self::assertSame(DecisionStage::IMPLICIT, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertEquals([
            self::entry(DecisionStage::ALLOW, TraceOutcome::CONDITION_FAILED, 'cond-pol', 0, ['input.tenant' => false]),
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
                ['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => ['input.tenant' => 'org-1']]],
                ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['posts/1']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['input' => ['tenant' => 'org-2']]);

        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'p', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::CONDITION_FAILED, 'p', 1, ['input.tenant' => false]),
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
                'conditions' => ['eq' => ['input.tenant' => 'org-1']],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['input' => ['tenant' => 'org-2']]);

        self::assertEquals(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], [
            self::entry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 'p', 0, ['input.tenant' => false]),
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
                    'conditions' => ['eq' => ['input.x' => 'blocked']],
                ],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read');

        self::assertEquals(Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [self::reference('deny-missing', 1)], [
            self::entry(DecisionStage::DENY, TraceOutcome::UNDECIDABLE, 'deny-missing', 1, ['input.x' => false]),
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
                'conditions' => ['eq' => ['input.x' => 'yes']],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['input' => ['y' => 'yes']]);

        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, 'allow-missing', 0, ['input.x' => false]),
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
                'resources' => ['tenants/${input.tenant}/*'],
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
                'resources' => ['tenants/${input.tenant}/*'],
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
                    'conditions' => ['gt' => ['input.n' => '${input.limit}']],
                ],
                ['effect' => 'allow', 'actions' => ['posts:read']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['input' => ['n' => 5, 'limit' => 'abc']]);

        self::assertEquals(Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [self::reference('deny-substituted', 0)], [
            self::entry(DecisionStage::DENY, TraceOutcome::UNDECIDABLE, 'deny-substituted', 0, ['input.n' => false]),
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
                'conditions' => ['gt' => ['input.n' => '${input.limit}']],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['input' => ['n' => 5, 'limit' => 'abc']]);

        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, 'allow-substituted', 0, ['input.n' => false]),
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
            new Statement(PolicyEffect::ALLOW, ['posts:read'], ['*'], ['eq' => ['input.k' => [1]]]),
            new Statement(PolicyEffect::ALLOW, ['posts:read']),
        ]);

        $last = Policy::fromArray([
            'name'       => 'last',
            'statements' => [['effect' => 'deny', 'actions' => ['users:read']]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$first, $broken, $last], 'posts:read', null, ['input' => ['k' => 1]]);

        self::assertEquals(Decision::deny(DecisionReason::INVALID_POLICY, DecisionStage::ALLOW, [self::reference('broken', 0)], [
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'last', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::INVALID, 'broken', 0, ['input.k' => false]),
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
            new Statement(PolicyEffect::DENY, ['posts:read'], ['*'], ['eq' => ['input.k' => [1]]]),
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['input' => ['k' => 1]]);

        self::assertEquals(Decision::deny(DecisionReason::INVALID_POLICY, DecisionStage::DENY, [self::reference('broken', 1)], [
            self::entry(DecisionStage::DENY, TraceOutcome::INVALID, 'broken', 1, ['input.k' => false]),
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
            new Statement(PolicyEffect::DENY, ['posts:read'], ['*'], ['eq' => ['input.k' => [1]]]),
            new Statement(PolicyEffect::DENY, ['posts:read']),
        ]);

        $last = Policy::fromArray([
            'name'       => 'last',
            'statements' => [['effect' => 'deny', 'actions' => ['posts:read']]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$first, $broken, $last], 'posts:read', null, ['input' => ['k' => 1]]);

        self::assertEquals(Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [self::reference('broken', 1), self::reference('last', 0)], [
            self::entry(DecisionStage::DENY, TraceOutcome::INVALID, 'broken', 0, ['input.k' => false]),
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
            new Statement(PolicyEffect::DENY, ['users:*'], ['*'], ['eq' => ['input.k' => [1]]]),
            new Statement(PolicyEffect::ALLOW, ['posts:read']),
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['input' => ['k' => 1]]);

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
                        'eq' => ['input.missing' => 'a', 'input.tenant' => 'org-1'],
                    ],
                ],
                [
                    'effect'     => 'deny',
                    'actions'    => ['posts:read'],
                    'conditions' => [
                        'eq' => ['input.tenant' => 'org-1', 'input.missing' => 'a'],
                    ],
                ],
                ['effect' => 'allow', 'actions' => ['posts:read']],
            ],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['input' => ['tenant' => 'org-2']]);

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('deny-mixed', 2)], [
            self::entry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 'deny-mixed', 0, ['input.missing' => false, 'input.tenant' => false]),
            self::entry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 'deny-mixed', 1, ['input.tenant' => false, 'input.missing' => false]),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'deny-mixed', 2),
        ]), $decision);
        self::assertSame(['input.missing', 'input.tenant'], \array_keys($decision->trace[0]->conditions));
        self::assertSame(['input.tenant', 'input.missing'], \array_keys($decision->trace[1]->conditions));
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
                    'conditions' => ['ip_in' => ['input.ip' => '2001:db8::/32']],
                ],
                ['effect' => 'allow', 'actions' => ['posts:read']],
            ],
        ]);

        $evaluator = new PolicyEvaluator;

        $inside = $evaluator->evaluate([$policy], 'posts:read', null, ['input' => ['ip' => '2001:db8::1']]);

        self::assertEquals(Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [self::reference('deny-ipv6', 0)], [
            self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'deny-ipv6', 0, ['input.ip' => true]),
        ]), $inside);

        $outside = $evaluator->evaluate([$policy], 'posts:read', null, ['input' => ['ip' => '2001:db9::1']]);

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('deny-ipv6', 1)], [
            self::entry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 'deny-ipv6', 0, ['input.ip' => false]),
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
                'conditions' => ['eq' => ['input.tenant' => 'org-1'], 'in' => ['input.role' => ['admin']]],
            ]],
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, ['input' => ['tenant' => 'org-1', 'role' => 'guest']]);

        self::assertSame(['input.tenant' => true, 'input.role' => false], $decision->trace[0]->conditions);
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
     * Each statement's sid reaches its reference, in the decision and in the
     * trace, and a statement without one is referenced without it.
     *
     * @return void
     */
    public function testReferencesCarryTheStatementSid(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [
                ['sid' => 'DenyDelete', 'effect' => 'deny', 'actions' => ['posts:delete']],
                ['sid' => 'AllowRead', 'effect' => 'allow', 'actions' => ['posts:read']],
                ['effect' => 'allow', 'actions' => ['posts:*']],
            ],
        ])->withId('key');

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read');

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('p', 1, 'key', 'AllowRead'), self::reference('p', 2, 'key')], [
            new TraceEntry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, self::reference('p', 0, 'key', 'DenyDelete')),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, self::reference('p', 1, 'key', 'AllowRead')),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, self::reference('p', 2, 'key')),
        ]), $decision);
        self::assertSame('p[key]#1 sid="AllowRead"', $decision->statements[0]->toString());
    }

    /**
     * A sid never changes the decision or the order statements are assessed in:
     * the same document with and without sids decides alike.
     *
     * @return void
     */
    public function testSidNeverChangesTheDecision(): void
    {
        $statements = [
            ['effect' => 'allow', 'actions' => ['posts:read']],
            ['effect' => 'deny', 'actions' => ['posts:read'], 'conditions' => ['eq' => ['input.tenant' => 'org-1']]],
        ];

        $plain = Policy::fromArray(['name' => 'p', 'statements' => $statements]);
        $named = Policy::fromArray(['name' => 'p', 'statements' => [['sid' => 'Z', ...$statements[0]], ['sid' => 'A', ...$statements[1]]]]);

        foreach ([['input' => ['tenant' => 'org-1']], ['input' => ['tenant' => 'org-2']]] as $context) {
            $left  = (new PolicyEvaluator)->evaluate([$plain], 'posts:read', null, $context);
            $right = (new PolicyEvaluator)->evaluate([$named], 'posts:read', null, $context);

            self::assertSame($left->reason, $right->reason);
            self::assertSame(
                \array_map(static fn (StatementReference $reference): int => $reference->index, $left->statements),
                \array_map(static fn (StatementReference $reference): int => $reference->index, $right->statements),
            );
            self::assertSame(
                \array_map(static fn (TraceEntry $entry): ?int => $entry->statement?->index, $left->trace),
                \array_map(static fn (TraceEntry $entry): ?int => $entry->statement?->index, $right->trace),
            );
        }
    }

    /**
     * A deny with not_actions denies every action its patterns do not name, and
     * is not applicable to one they do.
     *
     * @return void
     */
    public function testNotActionsDenyCoversEveryOtherAction(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'read-only',
            'statements' => [
                ['effect' => 'deny', 'not_actions' => ['posts:read', 'posts:list']],
                ['effect' => 'allow', 'actions' => ['posts:*']],
            ],
        ]);

        $evaluator = new PolicyEvaluator;

        self::assertSame(DecisionReason::EXPLICIT_DENY, $evaluator->evaluate([$policy], 'posts:delete')->reason);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $evaluator->evaluate([$policy], 'users:read')->reason);
        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('read-only', 1)], [
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'read-only', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'read-only', 1),
        ]), $evaluator->evaluate([$policy], 'posts:list'));
    }

    /**
     * A deny with not_resources denies every resource its patterns do not name,
     * is not applicable to one they do, and never applies to a check without a
     * resource.
     *
     * @return void
     */
    public function testNotResourcesDenyCoversEveryOtherResourceButNoResourcelessCheck(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'only-post-1',
            'statements' => [
                ['effect' => 'deny', 'actions' => ['posts:read'], 'not_resources' => ['post:1']],
                ['effect' => 'allow', 'actions' => ['posts:read']],
            ],
        ]);

        $evaluator = new PolicyEvaluator;

        self::assertSame(DecisionReason::EXPLICIT_DENY, $evaluator->evaluate([$policy], 'posts:read', 'post:2')->reason);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $evaluator->evaluate([$policy], 'posts:read', 'post:*')->reason);
        self::assertTrue($evaluator->evaluate([$policy], 'posts:read', 'post:1')->isAllowed());
        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('only-post-1', 1)], [
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'only-post-1', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'only-post-1', 1),
        ]), $evaluator->evaluate([$policy], 'posts:read'));
    }

    /**
     * A deny whose test passes only because `_if_exists` let a missing key
     * through applies like any other deny, while a present key it rules out
     * leaves the allow to decide.
     *
     * @return void
     */
    public function testDenyPassingUnderIfExistsApplies(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'network',
            'statements' => [
                ['effect' => 'deny', 'actions' => ['posts:read'], 'conditions' => ['ip_not_in_if_exists' => ['input.ip' => '10.0.0.0/8']]],
                ['effect' => 'allow', 'actions' => ['posts:read']],
            ],
        ]);

        $evaluator = new PolicyEvaluator;

        self::assertEquals(Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [self::reference('network', 0)], [
            self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'network', 0, ['input.ip' => true]),
        ]), $evaluator->evaluate([$policy], 'posts:read'));
        self::assertTrue($evaluator->evaluate([$policy], 'posts:read', null, ['input' => ['ip' => '10.1.1.1']])->isAllowed());
        self::assertSame(DecisionReason::EXPLICIT_DENY, $evaluator->evaluate([$policy], 'posts:read', null, ['input' => ['ip' => '8.8.8.8']])->reason);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $evaluator->evaluate([$policy], 'posts:read', null, ['input' => ['ip' => 'not-an-ip']])->reason);
    }

    /**
     * The check's context is read through dot paths, and a top-level key named
     * like a path never stands in for one.
     *
     * @return void
     */
    public function testConditionsReadTheContextByDotPath(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'by-path',
            'statements' => [[
                'effect'     => 'allow',
                'actions'    => ['posts:read'],
                'conditions' => ['eq' => ['input.post.status' => 'draft']],
            ]],
        ]);
        $evaluator = new PolicyEvaluator;

        self::assertTrue($evaluator->evaluate([$policy], 'posts:read', null, ['input' => ['post' => ['status' => 'draft']]])->isAllowed());
        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], [
            self::entry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, 'by-path', 0, ['input.post.status' => false]),
        ]), $evaluator->evaluate([$policy], 'posts:read', null, ['input.post.status' => 'draft']));
    }

    /**
     * Within one check a namespace is built only when a statement that names
     * the action reads it, once however many statements of either stage read
     * it, and a namespace no statement reads is never built; the next check
     * builds its own.
     *
     * @return void
     */
    public function testNamespacesAreBuiltLazilyAndOncePerCheck(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'lazy',
            'statements' => [
                ['effect' => 'deny', 'actions' => ['posts:read'], 'conditions' => ['ip_in' => ['request.ip' => '192.168.0.0/16']]],
                ['effect' => 'deny', 'actions' => ['posts:delete'], 'conditions' => ['eq' => ['tenant.plan' => 'free']]],
                ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['tenants/${tenant.id}/*'], 'conditions' => ['eq' => ['request.method' => 'GET']]],
            ],
        ]);
        $calls     = [];
        $evaluator = new PolicyEvaluator;

        $first = $evaluator->evaluate([$policy], 'posts:read', 'tenants/org-1/posts', self::countingContext($calls));

        self::assertTrue($first->isAllowed());
        self::assertSame(['request' => 1, 'tenant' => 1], $calls);

        $evaluator->evaluate([$policy], 'posts:read', 'tenants/org-1/posts', self::countingContext($calls));

        self::assertSame(['request' => 2, 'tenant' => 2], $calls);

        $evaluator->evaluate([$policy], 'posts:list', null, self::countingContext($calls));

        self::assertSame(['request' => 2, 'tenant' => 2], $calls);
    }

    /**
     * Build a check context with `request`, `tenant` and `environment`
     * namespaces, each built on demand, counting each build.
     *
     * @param  array<string, int>  $calls
     *
     * @param-out array<string, int>  $calls
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckContext
     */
    private static function countingContext(array &$calls): CheckContext
    {
        $values = [
            'request'     => ['ip' => '10.0.0.1', 'method' => 'GET'],
            'tenant'      => ['id' => 'org-1', 'plan' => 'pro'],
            'environment' => ['time' => '2026-01-31T09:30:00Z'],
        ];
        $builders = [];

        foreach ($values as $namespace => $namespaceValues) {
            $builders[$namespace] = static function () use (&$calls, $namespace, $namespaceValues): array {
                $calls[$namespace] = ($calls[$namespace] ?? 0) + 1;

                return [$namespace => $namespaceValues];
            };
        }

        return new CheckContext(['input' => []], $builders);
    }

    /**
     * Return a reference to the statement at the index of the named policy,
     * carrying the policy's stored key and the statement's sid when it has
     * them.
     *
     * @param  string  $policy
     * @param  int  $index
     * @param  string|null  $policyId
     * @param  string|null  $sid
     * @return \SineMacula\Laravel\Authorization\Evaluation\StatementReference
     */
    private static function reference(string $policy, int $index, ?string $policyId = null, ?string $sid = null): StatementReference
    {
        return new StatementReference($policy, $index, $policyId, $sid);
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
