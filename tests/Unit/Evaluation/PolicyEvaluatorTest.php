<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;

/**
 * Unit tests for the four IAM evaluation branches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PolicyEvaluator::class)]
final class PolicyEvaluatorTest extends TestCase
{
    /**
     * No policies / no match → implicit deny.
     *
     * @return void
     */
    public function testImplicitDenyWhenNoPolicies(): void
    {
        $result = (new PolicyEvaluator())->evaluate([], 'posts:create');

        self::assertFalse($result->allowed);
        self::assertSame(EvaluationResult::REASON_IMPLICIT_DENY, $result->reason);
        self::assertSame([], $result->trace);
    }

    /**
     * Only allow matches → explicit allow.
     *
     * @return void
     */
    public function testExplicitAllow(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
        ]);

        $result = (new PolicyEvaluator())->evaluate([$policy], 'posts:create');

        self::assertTrue($result->allowed);
        self::assertSame(EvaluationResult::REASON_EXPLICIT_ALLOW, $result->reason);
        self::assertNotNull($result->matchedStatement);
        self::assertCount(1, $result->trace);
        self::assertSame('matched', $result->trace[0]['decision']);
    }

    /**
     * Only deny matches → explicit deny.
     *
     * @return void
     */
    public function testExplicitDeny(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [['effect' => 'deny', 'actions' => ['posts:create']]],
        ]);

        $result = (new PolicyEvaluator())->evaluate([$policy], 'posts:create');

        self::assertFalse($result->allowed);
        self::assertSame(EvaluationResult::REASON_EXPLICIT_DENY, $result->reason);
    }

    /**
     * Allow + deny → explicit deny wins.
     *
     * @return void
     */
    public function testExplicitDenyOverridesAllow(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'p',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:create']],
                ['effect' => 'deny',  'actions' => ['posts:create']],
            ],
        ]);

        $result = (new PolicyEvaluator())->evaluate([$policy], 'posts:create');

        self::assertFalse($result->allowed);
        self::assertSame(EvaluationResult::REASON_EXPLICIT_DENY, $result->reason);
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

        $result = (new PolicyEvaluator())->evaluate([$policy], 'posts:create');

        self::assertTrue($result->allowed);
        self::assertCount(2, $result->trace);

        self::assertSame([
            'policy'          => 'named-policy',
            'statement_index' => 0,
            'decision'        => 'skipped',
            'reason'          => 'action/resource did not match',
        ], $result->trace[0]);

        self::assertSame([
            'policy'          => 'named-policy',
            'statement_index' => 1,
            'decision'        => 'matched',
            'reason'          => 'explicit allow',
        ], $result->trace[1]);
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

        $result = (new PolicyEvaluator())->evaluate([$policy], 'posts:delete');

        self::assertSame([
            'policy'          => 'deny-pol',
            'statement_index' => 0,
            'decision'        => 'matched',
            'reason'          => 'explicit deny',
        ], $result->trace[0]);
    }

    /**
     * The first matched allow is preserved across subsequent matches
     * (kills the AssignCoalesce mutation).
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

        $result = (new PolicyEvaluator())->evaluate([$policy], 'posts:read', 'first');

        self::assertNotNull($result->matchedStatement);
        // Both statements would match action; only the first matches resource,
        // so it must be the matched statement.
        self::assertSame(['first'], $result->matchedStatement->resources);
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

        $result = (new PolicyEvaluator())->evaluate([$policy], 'x', null, ['t' => 'b']);

        self::assertSame([
            'policy'          => 'cond-pol',
            'statement_index' => 0,
            'decision'        => 'skipped',
            'reason'          => 'conditions not satisfied',
        ], $result->trace[0]);
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

        $result = (new PolicyEvaluator())->evaluate([$policy], 'posts:create', null, ['tenant' => 'org-2']);

        self::assertFalse($result->allowed);
        self::assertSame(EvaluationResult::REASON_IMPLICIT_DENY, $result->reason);
        self::assertSame('skipped', $result->trace[0]['decision']);
        self::assertStringContainsString('conditions', $result->trace[0]['reason']);
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
                ['effect' => 'deny',  'actions' => ['posts:*']],
                ['effect' => 'allow', 'actions' => ['posts:*']],
            ],
        ]);

        $result = (new PolicyEvaluator())->evaluate([$policy], 'posts:create');

        self::assertFalse($result->allowed);
        self::assertCount(1, $result->trace);
    }
}
