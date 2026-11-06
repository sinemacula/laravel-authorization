<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\PrincipalSelectors;
use SineMacula\Laravel\Authorization\Evaluation\RequirementCheck;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubRequirementChecker;

/**
 * Unit tests for the policy evaluator's stages: the denies, the caps, the
 * allows and the implicit deny.
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
    /** @var array<string, array<string, int>> A requirement of multifactor within fifteen minutes. */
    private const array MULTIFACTOR = ['multifactor' => ['max_age' => 900]];

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
        self::assertSame([], self::steps($decision));
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

        self::assertEquals(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], self::staged([])), $decision);
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
        self::assertEquals([self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'p', 0)], self::steps($decision));
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
        self::assertEquals([self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'deny-pol', 0)], self::steps($decision));
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
        ], self::steps($decision));
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
        ], self::steps($decision));
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
        self::assertCount(3, self::steps($decision));

        $expected = [
            [DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 2, ['input.tenant' => false]],
            [DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 0, []],
            [DecisionStage::ALLOW, TraceOutcome::MATCHED, 1, []],
        ];

        foreach ($expected as $position => [$stage, $outcome, $index, $conditions]) {
            $entry = self::steps($decision)[$position];

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
        ], self::steps($decision));
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
        ], self::staged([
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'alpha', 0, [], 'z'),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'shared', 0, [], 'a'),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'shared', 0, [], 'b'),
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'shared', 1, [], 'b'),
        ]));

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
        ], self::staged([
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'shared', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'shared', 1),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'shared', 0),
        ]));

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

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('multi-allow', 0), self::reference('multi-allow', 2)], self::staged([
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'multi-allow', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'multi-allow', 1),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'multi-allow', 2),
        ])), $decision);
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

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('type-allow', 1)], self::staged([
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'type-allow', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'type-allow', 1),
        ])), $decision);
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
        ], self::steps($decision));
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

        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], self::staged([
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'p', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::CONDITION_FAILED, 'p', 1, ['input.tenant' => false]),
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'p', 2),
        ])), $decision);
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

        self::assertEquals(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], self::staged([
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'p', 1),
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'p', 0),
        ])), $decision);
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

        self::assertEquals(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], self::staged([
            self::entry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 'p', 0, ['input.tenant' => false]),
        ])), $decision);
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

        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], self::staged([
            self::entry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, 'allow-missing', 0, ['input.x' => false]),
        ])), $decision);
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

        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], self::staged([
            self::entry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, 'allow-unresolved', 0),
        ])), $decision);
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

        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], self::staged([
            self::entry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, 'allow-substituted', 0, ['input.n' => false]),
        ])), $decision);
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

        self::assertEquals(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], self::staged([
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'scoped', 0),
        ])), $decision);
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

        self::assertEquals(Decision::deny(DecisionReason::INVALID_POLICY, DecisionStage::ALLOW, [self::reference('broken', 0)], self::staged([
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'last', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::INVALID, 'broken', 0, ['input.k' => false]),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'broken', 1),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'first', 0),
        ])), $decision);
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

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('broken', 1)], self::staged([
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'broken', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'broken', 1),
        ])), $decision);
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

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('deny-mixed', 2)], self::staged([
            self::entry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 'deny-mixed', 0, ['input.missing' => false, 'input.tenant' => false]),
            self::entry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 'deny-mixed', 1, ['input.tenant' => false, 'input.missing' => false]),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'deny-mixed', 2),
        ])), $decision);
        self::assertSame(['input.missing', 'input.tenant'], \array_keys(self::steps($decision)[0]->conditions));
        self::assertSame(['input.tenant', 'input.missing'], \array_keys(self::steps($decision)[1]->conditions));
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

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('deny-ipv6', 1)], self::staged([
            self::entry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, 'deny-ipv6', 0, ['input.ip' => false]),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'deny-ipv6', 1),
        ])), $outside);
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

        self::assertSame(['input.tenant' => true, 'input.role' => false], self::steps($decision)[0]->conditions);
        self::assertSame(TraceOutcome::CONDITION_FAILED, self::steps($decision)[0]->outcome);
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

        self::assertSame(self::steps($first)[0], self::steps($second)[0]);
        self::assertSame($first->statements[0], $second->statements[0]);
        self::assertNotSame(self::steps($first)[1], self::steps($second)[1]);
        self::assertEquals(self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'p', 0), self::steps($first)[0]);
    }

    /**
     * The step a cap stage adds when it caps nothing is made once per evaluator
     * and shared by its every decision, and another evaluator makes its own.
     *
     * @return void
     */
    public function testTheUncappedStepsAreMadeOncePerEvaluator(): void
    {
        $evaluator = new PolicyEvaluator;
        $first     = $evaluator->evaluate([], 'posts:read');
        $second    = $evaluator->evaluate([], 'posts:edit');
        $other     = (new PolicyEvaluator)->evaluate([], 'posts:read');

        self::assertEquals(self::uncapped(DecisionStage::GUARDRAIL, DecisionStage::BOUNDARY, DecisionStage::SESSION), \array_slice($first->trace, 0, 3));

        foreach ([0, 1, 2] as $index) {
            self::assertSame($first->trace[$index], $second->trace[$index]);
            self::assertNotSame($first->trace[$index], $other->trace[$index]);
        }
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

        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('p', 1, 'key', 'AllowRead'), self::reference('p', 2, 'key')], self::staged([
            new TraceEntry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, self::reference('p', 0, 'key', 'DenyDelete')),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, self::reference('p', 1, 'key', 'AllowRead')),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, self::reference('p', 2, 'key')),
        ])), $decision);
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
                \array_map(static fn (TraceEntry $entry): ?int => $entry->statement?->index, self::steps($left)),
                \array_map(static fn (TraceEntry $entry): ?int => $entry->statement?->index, self::steps($right)),
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
        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('read-only', 1)], self::staged([
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'read-only', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'read-only', 1),
        ])), $evaluator->evaluate([$policy], 'posts:list'));
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
        self::assertEquals(Decision::allow(DecisionStage::ALLOW, [self::reference('only-post-1', 1)], self::staged([
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'only-post-1', 0),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'only-post-1', 1),
        ])), $evaluator->evaluate([$policy], 'posts:read'));
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
        self::assertEquals(Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], self::staged([
            self::entry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, 'by-path', 0, ['input.post.status' => false]),
        ])), $evaluator->evaluate([$policy], 'posts:read', null, ['input.post.status' => 'draft']));
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
     * An allow statement whose requirement alone is unmet denies as
     * insufficient_authentication at the implicit stage, decided by that
     * statement and carrying its requirement and unmet parts, the trace
     * recording the key `authentication` as not held.
     *
     * @return void
     */
    public function testAnUnmetRequirementAloneIsInsufficientAuthentication(): void
    {
        $policy   = self::policy('p', [self::requiringAllow(self::MULTIFACTOR)]);
        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(RequirementResult::unmet(['multifactor'])));

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $decision->reason);
        self::assertSame(DecisionStage::IMPLICIT, $decision->stage);
        self::assertEquals([self::reference('p', 0)], $decision->statements);
        self::assertEquals([new UnmetRequirement(AuthenticationRequirement::fromOperand(self::MULTIFACTOR), ['multifactor'])], $decision->requirements);
        self::assertEquals([self::entry(DecisionStage::ALLOW, TraceOutcome::CONDITION_FAILED, 'p', 0, ['authentication' => false])], self::steps($decision));
    }

    /**
     * Several allow statements whose requirements alone are unmet are each a
     * candidate, in the order they were assessed, and an allow whose other
     * condition fails is not.
     *
     * @return void
     */
    public function testSeveralCandidatesAreAlternatives(): void
    {
        $policy = self::policy('p', [
            self::requiringAllow(self::MULTIFACTOR),
            self::requiringAllow(self::MULTIFACTOR, ['eq' => ['input.k' => 'a']]),
            self::requiringAllow(['phishing_resistant' => []]),
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(RequirementResult::unmet([]), ['k' => 'b']));

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $decision->reason);
        self::assertEquals([self::reference('p', 0), self::reference('p', 2)], $decision->statements);
        self::assertEquals([
            new UnmetRequirement(AuthenticationRequirement::fromOperand(self::MULTIFACTOR), ['multifactor']),
            new UnmetRequirement(AuthenticationRequirement::fromOperand(['phishing_resistant' => []]), ['phishing_resistant']),
        ], $decision->requirements);
    }

    /**
     * Another allow that applies allows the check, whatever requirement goes
     * unmet.
     *
     * @return void
     */
    public function testAnotherAllowAllowsOverAnUnmetRequirement(): void
    {
        $policy   = self::policy('p', [self::requiringAllow(self::MULTIFACTOR), ['effect' => 'allow', 'actions' => ['posts:read']]]);
        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(RequirementResult::unmet(['multifactor'])));

        self::assertTrue($decision->isAllowed());
        self::assertEquals([self::reference('p', 1)], $decision->statements);
        self::assertSame([], $decision->requirements);
    }

    /**
     * A deny that applies denies the check over an unmet requirement.
     *
     * @return void
     */
    public function testADenyWinsOverAnUnmetRequirement(): void
    {
        $policy   = self::policy('p', [self::requiringAllow(self::MULTIFACTOR), ['effect' => 'deny', 'actions' => ['posts:read']]]);
        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(RequirementResult::unmet(['multifactor'])));

        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame([], $decision->requirements);
    }

    /**
     * An invalid allow statement denies the check as invalid_policy over an
     * unmet requirement.
     *
     * @return void
     */
    public function testAnInvalidPolicyBlocksInsufficientAuthentication(): void
    {
        $invalid  = new Policy('q', [new Statement(PolicyEffect::ALLOW, ['posts:read'], null, ['bogus' => ['input.k' => 1]])]);
        $policy   = self::policy('p', [self::requiringAllow(self::MULTIFACTOR)]);
        $decision = (new PolicyEvaluator)->evaluate([$policy, $invalid], 'posts:read', null, self::requirementContext(RequirementResult::unmet(['multifactor'])));

        self::assertSame(DecisionReason::INVALID_POLICY, $decision->reason);
        self::assertSame([], $decision->requirements);
    }

    /**
     * A requirement that cannot be checked on an allow statement is a failed
     * condition, never insufficient authentication.
     *
     * @return void
     */
    public function testAnUndecidableRequirementOnAnAllowIsAFailedCondition(): void
    {
        $policy   = self::policy('p', [self::requiringAllow(self::MULTIFACTOR)]);
        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(new \RuntimeException('down')));

        self::assertSame(DecisionReason::CONDITION_FAILED, $decision->reason);
        self::assertSame([], $decision->requirements);
        self::assertEquals([self::entry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, 'p', 0, ['authentication' => false])], self::steps($decision));
    }

    /**
     * A met requirement on an allow statement allows the check.
     *
     * @return void
     */
    public function testAMetRequirementOnAnAllowAllows(): void
    {
        $policy   = self::policy('p', [self::requiringAllow(self::MULTIFACTOR)]);
        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(RequirementResult::met()));

        self::assertTrue($decision->isAllowed());
        self::assertEquals([self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'p', 0, ['authentication' => true])], self::steps($decision));
    }

    /**
     * On a deny statement an unmet requirement is a test that does not hold, so
     * the deny does not apply; a met one applies it, and one that cannot be
     * checked applies it too.
     *
     * @return void
     */
    public function testARequirementOnADeny(): void
    {
        $policy = self::policy('p', [
            ['effect' => 'deny', 'actions' => ['posts:read'], 'conditions' => ['authentication_requirement' => ['authentication' => self::MULTIFACTOR]]],
            ['effect' => 'allow', 'actions' => ['posts:read']],
        ]);

        $unmet       = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(RequirementResult::unmet(['multifactor'])));
        $met         = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(RequirementResult::met()));
        $undecidable = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(new \RuntimeException('down')));

        self::assertTrue($unmet->isAllowed());
        self::assertSame(TraceOutcome::CONDITION_FAILED, self::steps($unmet)[0]->outcome);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $met->reason);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $undecidable->reason);
        self::assertSame(TraceOutcome::UNDECIDABLE, self::steps($undecidable)[0]->outcome);
    }

    /**
     * An unmet requirement on a deny is never a candidate, so a check that
     * nothing else allows is no_match.
     *
     * @return void
     */
    public function testAnUnmetRequirementOnADenyIsNoCandidate(): void
    {
        $deny     = ['effect' => 'deny', 'actions' => ['posts:read'], 'conditions' => ['authentication_requirement' => ['authentication' => self::MULTIFACTOR]]];
        $policy   = self::policy('p', [$deny]);
        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(RequirementResult::unmet(['multifactor'])));

        self::assertSame(DecisionReason::NO_MATCH, $decision->reason);
        self::assertSame([], $decision->requirements);
    }

    /**
     * Insufficient authentication wins over another allow whose conditions
     * fail.
     *
     * @return void
     */
    public function testInsufficientAuthenticationWinsOverAFailedCondition(): void
    {
        $policy = self::policy('p', [
            ['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => ['input.k' => 'a']]],
            self::requiringAllow(self::MULTIFACTOR),
        ]);

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(RequirementResult::unmet(['multifactor']), ['k' => 'b']));

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $decision->reason);
        self::assertEquals([self::reference('p', 1)], $decision->statements);
    }

    /**
     * A decision that read a requirement carries the session and the earliest
     * instant a met requirement stays met until; one that read none carries no
     * freshness.
     *
     * @return void
     */
    public function testTheDecisionCarriesItsFreshness(): void
    {
        $until    = new \DateTimeImmutable('2100-01-01 00:00:00');
        $policy   = self::policy('p', [self::requiringAllow(self::MULTIFACTOR)]);
        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(RequirementResult::met($until)));
        $denied   = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, self::requirementContext(RequirementResult::unmet(['multifactor'])));
        $open     = self::policy('p', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $plain    = (new PolicyEvaluator)->evaluate([$open], 'posts:read', null, self::requirementContext(RequirementResult::met()));

        self::assertEquals(new RequirementFreshness('session-1', $until), $decision->freshness);
        self::assertEquals(new RequirementFreshness('session-1'), $denied->freshness);
        self::assertNull($plain->freshness);
    }

    /**
     * A resource policy's allow applies to a subject its principals name, at
     * the allow stage, decided by the statement, which names the resource its
     * policy is attached to; it does not apply to a subject they do not name,
     * nor to any subject without the context naming one, and the trace says so.
     *
     * @return void
     */
    public function testAResourcePolicysAllowAppliesOnlyToTheSubjectsItNames(): void
    {
        $policy = self::policy('sharing', [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:2', 'user:1']]])->withId('key')->withResource('posts:7');
        $named  = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', 'posts:7', self::namedContext('1'));

        self::assertTrue($named->isAllowed());
        self::assertSame(DecisionStage::ALLOW, $named->stage);
        self::assertEquals([new StatementReference('sharing', 0, 'key', null, 'posts:7')], $named->statements);
        self::assertSame(TraceOutcome::MATCHED, self::steps($named)[0]->outcome);

        foreach ([self::namedContext('3'), new CheckContext] as $context) {
            $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', 'posts:7', $context);

            self::assertSame(DecisionReason::NO_MATCH, $decision->reason);
            self::assertSame(DecisionStage::IMPLICIT, $decision->stage);
            $reference = new StatementReference('sharing', 0, 'key', null, 'posts:7');

            self::assertEquals([new TraceEntry(DecisionStage::ALLOW, TraceOutcome::PRINCIPAL_MISMATCH, $reference)], self::steps($decision));
        }

        $other = (new PolicyEvaluator)->evaluate([$policy], 'posts:edit', 'posts:7', self::namedContext('1'));

        self::assertSame(TraceOutcome::NOT_APPLICABLE, self::steps($other)[0]->outcome);
    }

    /**
     * An allow that does not fit its source applies to nobody: a resource
     * policy's allow naming no principals, and an allow naming principals in a
     * policy attached any other way, the subject named or not.
     *
     * @return void
     */
    public function testAnAllowThatDoesNotFitItsSourceAppliesToNobody(): void
    {
        $unnamed    = self::policy('unnamed', [['effect' => 'allow', 'actions' => ['posts:read']]])->withResource('posts:*');
        $misplaced  = self::policy('misplaced', [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']]]);
        $identities = self::policy('identity', [['effect' => 'allow', 'actions' => ['posts:read']]]);

        foreach ([$unnamed, $misplaced] as $policy) {
            $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', 'posts:7', self::namedContext('1'));

            self::assertSame(DecisionReason::NO_MATCH, $decision->reason);
            self::assertSame(TraceOutcome::PRINCIPAL_MISMATCH, self::steps($decision)[0]->outcome);
        }

        self::assertTrue((new PolicyEvaluator)->evaluate([$identities], 'posts:read', 'posts:7', self::namedContext('1'))->isAllowed());
    }

    /**
     * A resource policy's deny applies to everyone at the deny stage, over an
     * allow from any source, the subject named or not.
     *
     * @return void
     */
    public function testAResourcePolicysDenyAppliesToEveryone(): void
    {
        $locked = self::policy('locked', [['sid' => 'lock', 'effect' => 'deny', 'actions' => ['posts:delete']]])->withResource('posts:7');
        $mine   = self::policy('mine', [['effect' => 'allow', 'actions' => ['posts:delete']]]);

        foreach ([self::namedContext('1'), new CheckContext] as $context) {
            $decision = (new PolicyEvaluator)->evaluate([$mine, $locked], 'posts:delete', 'posts:7', $context);

            self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
            self::assertEquals([new StatementReference('locked', 0, null, 'lock', 'posts:7')], $decision->statements);
            self::assertCount(1, self::steps($decision));
        }
    }

    /**
     * An allow whose principals do not name the subject never makes the
     * decision `insufficient_authentication` or `condition_failed`: it bears on
     * nothing.
     *
     * @return void
     */
    public function testAMismatchedAllowBearsOnNothing(): void
    {
        $policy = self::policy('sharing', [
            ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:2'], 'conditions' => ['eq' => ['input.flag' => 'on']]],
            [...self::requiringAllow(['phishing_resistant' => []]), 'principals' => ['user:2']],
        ])->withResource('posts:7');

        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', 'posts:7', self::namedContext('1'));

        self::assertSame(DecisionReason::NO_MATCH, $decision->reason);
        $outcomes = \array_map(static fn (TraceEntry $entry): TraceOutcome => $entry->outcome, self::steps($decision));

        self::assertSame([TraceOutcome::PRINCIPAL_MISMATCH, TraceOutcome::PRINCIPAL_MISMATCH], $outcomes);
    }

    /**
     * One policy attached as a resource policy and to the subject is ordered by
     * the resource after its name and key, so the decision is the same whatever
     * order the policies come in.
     *
     * @return void
     */
    public function testAPolicyAttachedTwoWaysIsOrderedByTheResource(): void
    {
        $identity = self::policy('denies', [['effect' => 'deny', 'actions' => ['posts:delete']]])->withId('key');
        $resource = $identity->withResource('posts:7');

        foreach (self::permutations([$identity, $resource]) as $policies) {
            $decision = (new PolicyEvaluator)->evaluate($policies, 'posts:delete', 'posts:7');

            self::assertEquals([new StatementReference('denies', 0, 'key'), new StatementReference('denies', 0, 'key', null, 'posts:7')], $decision->statements);
        }
    }

    /**
     * Every stage a decision reaches is traced, in AUTHZ-7.1's order: the
     * denies, then each cap stage, which caps nothing when nothing applies,
     * then the allows and the permission step.
     *
     * @return void
     */
    public function testEveryStageIsTracedInOrder(): void
    {
        $policy   = self::policy('p', [['effect' => 'deny', 'actions' => ['posts:delete']], ['effect' => 'allow', 'actions' => ['posts:edit']]]);
        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, [], [], static fn (): bool => false);

        self::assertEquals([
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'p', 0),
            ...self::uncapped(DecisionStage::GUARDRAIL, DecisionStage::BOUNDARY, DecisionStage::SESSION),
            self::entry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, 'p', 1),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD),
        ], $decision->trace);
        self::assertSame(DecisionReason::NO_MATCH, $decision->reason);
    }

    /**
     * A deny ends the decision before any cap or allow is reached, so the
     * permission is never asked.
     *
     * @return void
     */
    public function testADenyEndsTheDecisionBeforeTheCapsAndTheAllows(): void
    {
        $asked    = new \ArrayObject;
        $policy   = self::policy('p', [['effect' => 'deny', 'actions' => ['posts:read']], ['effect' => 'allow', 'actions' => ['posts:read']]]);
        $boundary = self::policy('cap', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, [], [$boundary], static function () use ($asked): bool {
            $asked->append(true);

            return true;
        });

        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertEquals([self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'p', 0)], $decision->trace);
        self::assertCount(0, $asked);
    }

    /**
     * A boundary that does not allow the check denies it as `boundary` at the
     * boundary stage, before any allow statement or permission is weighed.
     *
     * @return void
     */
    public function testABoundaryThatDoesNotAllowDeniesBeforeTheAllows(): void
    {
        $asked    = new \ArrayObject;
        $policy   = self::policy('p', [['effect' => 'allow', 'actions' => ['posts:edit']]]);
        $boundary = self::policy('cap', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:edit', null, [], [$boundary], static function () use ($asked): bool {
            $asked->append(true);

            return true;
        });

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::BOUNDARY, $decision->reason);
        self::assertSame(DecisionStage::BOUNDARY, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertEquals([
            ...self::uncapped(DecisionStage::GUARDRAIL),
            new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::NOT_APPLICABLE, self::reference('cap', 0)),
            self::refused('cap'),
        ], $decision->trace);
        self::assertCount(0, $asked);
        self::assertStringEndsWith('[boundary] cap: refused', $decision->explain());
    }

    /**
     * A boundary with no allow statement, or with deny statements alone, allows
     * nothing: it denies every check its denies do not as `boundary`, with a
     * step at the boundary stage that names it.
     *
     * @return void
     */
    public function testABoundaryWithNoAllowStatementDeniesNamingIt(): void
    {
        $allowAll = self::policy('all', [['effect' => 'allow', 'actions' => ['*']]]);
        $empty    = (new PolicyEvaluator)->evaluate([$allowAll], 'posts:write', null, [], [(new Policy('empty', []))->withId('9')], static fn (): bool => true);
        $denyOnly = (new PolicyEvaluator)->evaluate([$allowAll], 'posts:read', null, [], [self::policy('donly', [['effect' => 'deny', 'actions' => ['posts:delete']]])]);

        self::assertSame(DecisionReason::BOUNDARY, $empty->reason);
        self::assertSame(DecisionStage::BOUNDARY, $empty->stage);
        self::assertEquals([...self::uncapped(DecisionStage::GUARDRAIL), self::refused('empty[9]')], $empty->trace);
        self::assertStringContainsString('[boundary] empty[9]: refused', $empty->explain());

        self::assertSame(DecisionReason::BOUNDARY, $denyOnly->reason);
        self::assertSame(DecisionStage::BOUNDARY, $denyOnly->stage);
        self::assertEquals([
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'donly', 0),
            ...self::uncapped(DecisionStage::GUARDRAIL),
            self::refused('donly'),
        ], $denyOnly->trace);
    }

    /**
     * A policy held and set as a boundary too, or set as the boundary of both
     * grantees, is named once in the decision, and still plays each part: its
     * deny denies once, and as a boundary it still caps the check.
     *
     * @return void
     */
    public function testAPolicyReachedTwiceIsNamedOnce(): void
    {
        $both   = self::policy('both', [['effect' => 'allow', 'actions' => ['*']], ['effect' => 'deny', 'actions' => ['posts:delete']]]);
        $twin   = self::policy('both', [['effect' => 'allow', 'actions' => ['*']], ['effect' => 'deny', 'actions' => ['posts:delete']]]);
        $narrow = self::policy('narrow', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $denied = (new PolicyEvaluator)->evaluate([$both], 'posts:delete', null, [], [$twin]);

        self::assertSame(DecisionReason::EXPLICIT_DENY, $denied->reason);
        self::assertEquals([self::reference('both', 1)], $denied->statements);
        self::assertEquals([self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'both', 1)], $denied->trace);
        self::assertSame('DENY (explicit_deny: an applicable statement denies it) at the deny stage by both#1.', \explode("\n", $denied->explain())[0]);

        $allowed = (new PolicyEvaluator)->evaluate([$both], 'posts:read', null, [], [$both, $twin]);

        self::assertTrue($allowed->isAllowed());
        self::assertEquals([self::reference('both', 0)], $allowed->statements);
        self::assertEquals([
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'both', 1),
            ...self::uncapped(DecisionStage::GUARDRAIL),
            new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::MATCHED, self::reference('both', 0)),
            ...self::uncapped(DecisionStage::SESSION),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'both', 0),
        ], $allowed->trace);

        $capped = (new PolicyEvaluator)->evaluate([$narrow], 'posts:edit', null, [], [$narrow], static fn (): bool => true);

        self::assertSame(DecisionReason::BOUNDARY, $capped->reason);
    }

    /**
     * A boundary that allows the check lets the allows decide it: a boundary
     * grants nothing, so with nothing else allowing it the check is denied as
     * no match, and an allow statement or a permission held allows it.
     *
     * @return void
     */
    public function testABoundaryThatAllowsLetsTheAllowsDecide(): void
    {
        $boundary = self::policy('cap', [['effect' => 'allow', 'actions' => ['posts:*']]]);
        $policy   = self::policy('p', [['effect' => 'allow', 'actions' => ['posts:edit']]]);
        $alone    = (new PolicyEvaluator)->evaluate([], 'posts:read', null, [], [$boundary]);
        $allowed  = (new PolicyEvaluator)->evaluate([$policy], 'posts:edit', null, [], [$boundary]);
        $held     = (new PolicyEvaluator)->evaluate([], 'posts:read', null, [], [$boundary], static fn (): bool => true);

        self::assertSame(DecisionReason::NO_MATCH, $alone->reason);
        self::assertTrue($allowed->isAllowed());
        self::assertEquals([self::reference('p', 0)], $allowed->statements);
        self::assertEquals([
            ...self::uncapped(DecisionStage::GUARDRAIL),
            new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::MATCHED, self::reference('cap', 0)),
            ...self::uncapped(DecisionStage::SESSION),
            self::entry(DecisionStage::ALLOW, TraceOutcome::MATCHED, 'p', 0),
        ], $allowed->trace);
        self::assertTrue($held->isAllowed());
        self::assertSame([], $held->statements);
    }

    /**
     * Every boundary must allow the check: the boundaries are intersected, and
     * each is assessed whatever the others found, in a fixed order.
     *
     * @return void
     */
    public function testEveryBoundaryMustAllowTheCheck(): void
    {
        $wide   = self::policy('a-wide', [['effect' => 'allow', 'actions' => ['posts:*']]]);
        $narrow = self::policy('b-narrow', [['effect' => 'allow', 'actions' => ['posts:read']]]);

        foreach ([[$wide, $narrow], [$narrow, $wide]] as $boundaries) {
            $edit = (new PolicyEvaluator)->evaluate([], 'posts:edit', null, [], $boundaries, static fn (): bool => true);
            $read = (new PolicyEvaluator)->evaluate([], 'posts:read', null, [], $boundaries, static fn (): bool => true);

            self::assertSame(DecisionReason::BOUNDARY, $edit->reason);
            self::assertEquals([
                ...self::uncapped(DecisionStage::GUARDRAIL),
                new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::MATCHED, self::reference('a-wide', 0)),
                new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::NOT_APPLICABLE, self::reference('b-narrow', 0)),
                self::refused('b-narrow'),
            ], $edit->trace);
            self::assertTrue($read->isAllowed());
        }
    }

    /**
     * A boundary's allow is judged as an ordinary policy's, conditions
     * included: one whose conditions do not hold, or cannot be decided, does
     * not allow the check, and one that names principals applies to nobody.
     *
     * @return void
     */
    public function testABoundarysAllowIsJudgedWithItsConditions(): void
    {
        $boundary = self::policy('cap', [['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => ['input.region' => 'eu']]]]);
        $named    = self::policy('named', [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => ['user:1']]]);
        $evaluate = static fn (array $boundaries, array $input): Decision => (new PolicyEvaluator)
            ->evaluate([], 'posts:read', null, ['input' => $input], $boundaries, static fn (): bool => true);

        self::assertTrue($evaluate([$boundary], ['region' => 'eu'])->isAllowed());
        self::assertSame(DecisionReason::BOUNDARY, $evaluate([$boundary], ['region' => 'us'])->reason);
        self::assertSame(DecisionReason::BOUNDARY, $evaluate([$boundary], [])->reason);
        self::assertSame(TraceOutcome::UNDECIDABLE, $evaluate([$boundary], [])->trace[1]->outcome);

        $mismatched = (new PolicyEvaluator)->evaluate([], 'posts:read', null, self::namedContext('1'), [$named], static fn (): bool => true);

        self::assertSame(DecisionReason::BOUNDARY, $mismatched->reason);
        self::assertSame(TraceOutcome::PRINCIPAL_MISMATCH, $mismatched->trace[1]->outcome);
        self::assertSame(DecisionStage::BOUNDARY, $mismatched->trace[1]->stage);
    }

    /**
     * A boundary's deny statement denies at the deny stage, with the policies'
     * denies, the boundary's denies traced after them.
     *
     * @return void
     */
    public function testABoundarysDenyDeniesAtTheDenyStage(): void
    {
        $policy   = self::policy('z-own', [['effect' => 'deny', 'actions' => ['posts:delete']], ['effect' => 'allow', 'actions' => ['posts:read']]]);
        $boundary = self::policy('a-cap', [['effect' => 'allow', 'actions' => ['posts:*']], ['effect' => 'deny', 'actions' => ['posts:read']]]);
        $decision = (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, [], [$boundary]);

        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
        self::assertEquals([self::reference('a-cap', 1)], $decision->statements);
        self::assertEquals([
            self::entry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, 'z-own', 0),
            self::entry(DecisionStage::DENY, TraceOutcome::MATCHED, 'a-cap', 1),
        ], $decision->trace);
    }

    /**
     * A boundary statement that cannot be evaluated denies the check as an
     * invalid policy at the boundary stage, naming the statement, after every
     * boundary has been assessed.
     *
     * @return void
     */
    public function testAnInvalidBoundaryStatementDeniesAsAnInvalidPolicy(): void
    {
        $broken   = new Policy('a-broken', [new Statement(PolicyEffect::ALLOW, ['posts:read'], null, ['bogus' => ['input.k' => 1]])]);
        $allowing = self::policy('b-allowing', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $decision = (new PolicyEvaluator)->evaluate([], 'posts:read', null, [], [$allowing, $broken], static fn (): bool => true);

        self::assertSame(DecisionReason::INVALID_POLICY, $decision->reason);
        self::assertSame(DecisionStage::BOUNDARY, $decision->stage);
        self::assertEquals([self::reference('a-broken', 0)], $decision->statements);
        self::assertEquals([
            ...self::uncapped(DecisionStage::GUARDRAIL),
            new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::INVALID, self::reference('a-broken', 0)),
            self::refused('a-broken'),
            new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::MATCHED, self::reference('b-allowing', 0)),
        ], $decision->trace);
    }

    /**
     * An allow statement whose authentication requirement alone is unmet is
     * reported as insufficient authentication only once every boundary allows
     * the check; a boundary whose own requirement is unmet does not allow it,
     * and is never answered with a step-up.
     *
     * @return void
     */
    public function testInsufficientAuthenticationIsReachedOnlyOnceTheBoundariesPass(): void
    {
        $policy  = self::policy('p', [self::requiringAllow(self::MULTIFACTOR)]);
        $open    = self::policy('open', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $closed  = self::policy('closed', [['effect' => 'allow', 'actions' => ['posts:edit']]]);
        $stepped = self::policy('stepped', [self::requiringAllow(self::MULTIFACTOR)]);
        $unmet   = static fn (): CheckContext => self::requirementContext(RequirementResult::unmet(['multifactor']));

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, $unmet(), [$open])->reason);
        self::assertSame(DecisionReason::BOUNDARY, (new PolicyEvaluator)->evaluate([$policy], 'posts:read', null, $unmet(), [$closed])->reason);

        $capped = (new PolicyEvaluator)->evaluate([], 'posts:read', null, $unmet(), [$stepped], static fn (): bool => true);

        self::assertSame(DecisionReason::BOUNDARY, $capped->reason);
        self::assertSame([], $capped->requirements);
    }

    /**
     * The permission is asked once, only when no allow statement allowed and
     * none was invalid, and a permission held allows over a failed condition
     * and an unmet requirement.
     *
     * @return void
     */
    public function testThePermissionIsAskedOnlyWhenNoStatementAllows(): void
    {
        $asked      = new \ArrayObject;
        $permission = static function () use ($asked): bool {
            $asked->append(true);

            return true;
        };

        $allowing = self::policy('p', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $invalid  = new Policy('q', [new Statement(PolicyEffect::ALLOW, ['posts:read'], null, ['bogus' => ['input.k' => 1]])]);
        $failing  = self::policy('r', [['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => ['input.k' => 'a']]]]);

        self::assertTrue((new PolicyEvaluator)->evaluate([$allowing], 'posts:read', null, [], [], $permission)->isAllowed());
        self::assertSame(DecisionReason::INVALID_POLICY, (new PolicyEvaluator)->evaluate([$invalid], 'posts:read', null, [], [], $permission)->reason);
        self::assertCount(0, $asked);

        $held = (new PolicyEvaluator)->evaluate([$failing], 'posts:read', null, ['input' => ['k' => 'b']], [], $permission);

        self::assertTrue($held->isAllowed());
        self::assertSame(DecisionStage::ALLOW, $held->stage);
        self::assertSame([], $held->statements);
        self::assertEquals(new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD), $held->trace[\count($held->trace) - 1]);

        $stepUp = self::policy('s', [self::requiringAllow(self::MULTIFACTOR)]);
        $unmet  = self::requirementContext(RequirementResult::unmet(['multifactor']));

        self::assertTrue((new PolicyEvaluator)->evaluate([$stepUp], 'posts:read', null, $unmet, [], $permission)->isAllowed());
        self::assertCount(2, $asked);
    }

    /**
     * The decision over boundaries is the same whatever order the policies and
     * the boundaries were read in.
     *
     * @return void
     */
    public function testBoundariesAreDecidedInAFixedOrder(): void
    {
        $boundaries = [
            self::policy('c', [['effect' => 'allow', 'actions' => ['posts:read']]]),
            self::policy('a', [['effect' => 'allow', 'actions' => ['posts:*']], ['effect' => 'deny', 'actions' => ['posts:delete']]]),
            self::policy('b', [['effect' => 'allow', 'actions' => ['posts:read', 'posts:edit']]]),
        ];

        foreach (['posts:read', 'posts:edit', 'posts:delete'] as $action) {
            $evaluate  = static fn (array $order): Decision => (new PolicyEvaluator)->evaluate([], $action, null, [], $order, static fn (): bool => true);
            $decisions = \array_map($evaluate, self::permutations($boundaries));

            foreach ($decisions as $decision) {
                self::assertEquals($decisions[0], $decision, $action);
            }
        }
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
     * Return a context whose subject is `user:<id>`.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckContext
     */
    private static function namedContext(string $id): CheckContext
    {
        return new CheckContext(['input' => []], [], null, new PrincipalSelectors(new Subject(new Reference('user', $id))));
    }

    /**
     * Build a policy of the statement documents.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function policy(string $name, array $statements): Policy
    {
        return Policy::fromArray(['name' => $name, 'statements' => $statements]);
    }

    /**
     * Return an allow statement document for `posts:read` stating the
     * requirement, with any further conditions.
     *
     * @param  array<string, mixed>  $requirement
     * @param  array<string, mixed>  $conditions
     * @return array<string, mixed>
     */
    private static function requiringAllow(array $requirement, array $conditions = []): array
    {
        return ['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['authentication_requirement' => ['authentication' => $requirement], ...$conditions]];
    }

    /**
     * Build a context whose requirements the checker answers for a subject in
     * `session-1`, with the input given.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\RequirementResult|\Throwable  $answer
     * @param  array<string, mixed>  $input
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckContext
     */
    private static function requirementContext(RequirementResult|\Throwable $answer, array $input = []): CheckContext
    {
        $user = new \stdClass;

        return new CheckContext(['input' => $input], [], new RequirementCheck(new StubRequirementChecker($answer), new Subject($user, $user, session: 'session-1')));
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
     * Return the trace expected of a decision that reached the allow stage: the
     * deny stage's steps, then the step each cap stage adds when it caps
     * nothing (guardrails, boundaries, then session caps), then the rest.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>
     */
    private static function staged(array $trace): array
    {
        $denies = \array_values(\array_filter($trace, static fn (TraceEntry $entry): bool => $entry->stage === DecisionStage::DENY));
        $rest   = \array_values(\array_filter($trace, static fn (TraceEntry $entry): bool => $entry->stage !== DecisionStage::DENY));

        return [...$denies, ...self::uncapped(DecisionStage::GUARDRAIL, DecisionStage::BOUNDARY, DecisionStage::SESSION), ...$rest];
    }

    /**
     * Return the step a boundary adds when it refuses the check.
     *
     * @param  string  $boundary
     * @return \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
     */
    private static function refused(string $boundary): TraceEntry
    {
        return new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::REFUSED, null, [], $boundary);
    }

    /**
     * Return the step each of the cap stages adds when it caps nothing.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  ...$stages
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>
     */
    private static function uncapped(DecisionStage ...$stages): array
    {
        return \array_values(\array_map(static fn (DecisionStage $stage): TraceEntry => new TraceEntry($stage, TraceOutcome::UNCAPPED), $stages));
    }

    /**
     * Return the decision's trace without the step each cap stage adds when it
     * caps nothing, so a test reads the statements' and the permission's steps
     * alone.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>
     */
    private static function steps(Decision $decision): array
    {
        return \array_values(\array_filter($decision->trace, static fn (TraceEntry $entry): bool => $entry->outcome !== TraceOutcome::UNCAPPED));
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
