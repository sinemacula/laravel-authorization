<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceDecision;
use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * Unit tests for the evaluation result value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EvaluationResult::class)]
final class EvaluationResultTest extends TestCase
{
    /**
     * allowed() returns an explicit-allow result with the supplied statement.
     *
     * @return void
     */
    public function testAllowedFactory(): void
    {
        $statement = new Statement(PolicyEffect::ALLOW, ['x']);
        $result    = EvaluationResult::allowed($statement, [['policy' => 'p', 'statement_index' => 0, 'decision' => TraceDecision::MATCHED, 'reason' => 'explicit allow']]);

        self::assertTrue($result->allowed);
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, $result->reason);
        self::assertSame($statement, $result->matchedStatement);
        self::assertCount(1, $result->trace);
    }

    /**
     * explicitlyDenied() returns a deny result with the supplied statement.
     *
     * @return void
     */
    public function testExplicitlyDeniedFactory(): void
    {
        $statement = new Statement(PolicyEffect::DENY, ['x']);
        $result    = EvaluationResult::explicitlyDenied($statement);

        self::assertFalse($result->allowed);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $result->reason);
        self::assertSame($statement, $result->matchedStatement);
    }

    /**
     * implicitlyDenied() returns a deny result with no matched statement.
     *
     * @return void
     */
    public function testImplicitlyDeniedFactory(): void
    {
        $result = EvaluationResult::implicitlyDenied();

        self::assertFalse($result->allowed);
        self::assertSame(DecisionReason::IMPLICIT_DENY, $result->reason);
        self::assertNull($result->matchedStatement);
    }

    /**
     * rbacAllowed() returns an allow result with no matched statement.
     *
     * @return void
     */
    public function testRbacAllowedFactory(): void
    {
        $result = EvaluationResult::rbacAllowed();

        self::assertTrue($result->allowed);
        self::assertSame(DecisionReason::RBAC_ALLOW, $result->reason);
        self::assertNull($result->matchedStatement);
    }

    /**
     * explain() includes the trace entries.
     *
     * @return void
     */
    public function testExplainIncludesTraceEntries(): void
    {
        $trace = [
            ['policy' => 'p', 'statement_index' => 0, 'decision' => TraceDecision::MATCHED, 'reason' => 'explicit allow'],
            ['policy' => 'p', 'statement_index' => 1, 'decision' => TraceDecision::SKIPPED, 'reason' => 'conditions not satisfied'],
        ];

        $result = EvaluationResult::allowed(new Statement(PolicyEffect::ALLOW, ['x']), $trace);

        $explain = $result->explain();
        self::assertStringContainsString('ALLOW', $explain);
        self::assertStringContainsString('explicit allow', $explain);
        self::assertStringContainsString('[matched]', $explain);
        self::assertStringContainsString('[skipped]', $explain);
    }

    /**
     * explain() omits the trace section when empty.
     *
     * @return void
     */
    public function testExplainWithoutTrace(): void
    {
        $explain = EvaluationResult::implicitlyDenied()->explain();

        self::assertStringContainsString('DENY', $explain);
        self::assertStringNotContainsString('Trace:', $explain);
    }

    /**
     * explain() labels every reason code with human-friendly text.
     *
     * @return void
     */
    public function testExplainCoversEveryReason(): void
    {
        self::assertStringContainsString('RBAC grant', EvaluationResult::rbacAllowed()->explain());
        self::assertStringContainsString('explicit deny', EvaluationResult::explicitlyDenied(new Statement(PolicyEffect::DENY, ['x']))->explain());
        self::assertStringContainsString('implicit deny', EvaluationResult::implicitlyDenied()->explain());
    }
}
