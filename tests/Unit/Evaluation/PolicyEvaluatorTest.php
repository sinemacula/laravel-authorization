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
            'name'       => 'p',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['users:*']],
                ['effect' => 'allow', 'actions' => ['posts:create']],
            ],
        ]);

        $result = (new PolicyEvaluator())->evaluate([$policy], 'posts:create');

        self::assertTrue($result->allowed);
        self::assertCount(2, $result->trace);
        self::assertSame('skipped', $result->trace[0]['decision']);
        self::assertSame('matched', $result->trace[1]['decision']);
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
