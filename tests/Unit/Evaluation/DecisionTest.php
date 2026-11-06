<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;

/**
 * Unit tests for the decision value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Decision::class)]
final class DecisionTest extends TestCase
{
    /**
     * allow() returns an allow with no reason, decided at the stage, and
     * defaults to no statements and an empty trace.
     *
     * @return void
     */
    public function testAllowDefaultsStatementsAndTrace(): void
    {
        $decision = Decision::allow(DecisionStage::ALLOW);

        self::assertSame(DecisionEffect::ALLOW, $decision->effect);
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertSame([], $decision->trace);
    }

    /**
     * allow() keeps the supplied statements and trace untouched.
     *
     * @return void
     */
    public function testAllowKeepsStatementsAndTrace(): void
    {
        $statements = [new StatementReference('p', 0)];
        $trace      = [new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, $statements[0])];
        $decision   = Decision::allow(DecisionStage::ALLOW, $statements, $trace);

        self::assertSame(DecisionEffect::ALLOW, $decision->effect);
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertSame($statements, $decision->statements);
        self::assertSame($trace, $decision->trace);
    }

    /**
     * deny() returns a denial for the reason, decided at the stage, and
     * defaults to no statements and an empty trace.
     *
     * @return void
     */
    public function testDenyDefaultsStatementsAndTrace(): void
    {
        $decision = Decision::deny(DecisionReason::SUBJECT_INACTIVE, DecisionStage::SUBJECT);

        self::assertSame(DecisionEffect::DENY, $decision->effect);
        self::assertSame(DecisionReason::SUBJECT_INACTIVE, $decision->reason);
        self::assertSame(DecisionStage::SUBJECT, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertSame([], $decision->trace);
    }

    /**
     * deny() keeps the supplied statements and trace untouched.
     *
     * @return void
     */
    public function testDenyKeepsStatementsAndTrace(): void
    {
        $statements = [new StatementReference('p', 1), new StatementReference('q', 0)];
        $trace      = [
            new TraceEntry(DecisionStage::DENY, TraceOutcome::MATCHED, $statements[0]),
            new TraceEntry(DecisionStage::DENY, TraceOutcome::UNDECIDABLE, $statements[1]),
        ];
        $decision = Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, $statements, $trace);

        self::assertSame(DecisionEffect::DENY, $decision->effect);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
        self::assertSame($statements, $decision->statements);
        self::assertSame($trace, $decision->trace);
    }

    /**
     * isAllowed() is true for an allow and false for a denial.
     *
     * @return void
     */
    public function testIsAllowed(): void
    {
        self::assertTrue(Decision::allow(DecisionStage::ALLOW)->isAllowed());
        self::assertFalse(Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)->isAllowed());
    }

    /**
     * withStep() returns the decision with the entry appended to its trace,
     * keeping its effect, reason, stage and statements, and leaves the original
     * decision as it was.
     *
     * @return void
     */
    public function testWithStepAppendsToTheTrace(): void
    {
        $statements = [new StatementReference('p', 0)];
        $first      = new TraceEntry(DecisionStage::DENY, TraceOutcome::MATCHED, $statements[0]);
        $second     = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD);
        $original   = Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, $statements, [$first]);

        $decision = $original->withStep($second);

        self::assertNotSame($original, $decision);
        self::assertSame(DecisionEffect::DENY, $decision->effect);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
        self::assertSame($statements, $decision->statements);
        self::assertSame([$first, $second], $decision->trace);
        self::assertSame([$first], $original->trace);
    }

    /**
     * withStep() keeps an allow an allow, with no reason.
     *
     * @return void
     */
    public function testWithStepKeepsAnAllow(): void
    {
        $entry    = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD);
        $decision = Decision::allow(DecisionStage::ALLOW)->withStep($entry);

        self::assertSame(DecisionEffect::ALLOW, $decision->effect);
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertSame([$entry], $decision->trace);
    }

    /**
     * withPermission(true) turns a denial into an allow at the allow stage,
     * with no reason and no statements, its trace kept and a held step for the
     * permission appended.
     *
     * @return void
     */
    public function testWithPermissionHeldAllowsAtTheAllowStage(): void
    {
        $entry    = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::CONDITION_FAILED, new StatementReference('p', 0), ['owner' => false]);
        $original = Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [new StatementReference('p', 0)], [$entry]);

        $decision = $original->withPermission(true);

        self::assertSame(DecisionEffect::ALLOW, $decision->effect);
        self::assertTrue($decision->isAllowed());
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertCount(2, $decision->trace);
        self::assertSame($entry, $decision->trace[0]);
        self::assertEquals(new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD), $decision->trace[1]);
        self::assertSame([$entry], $original->trace);
        self::assertFalse($original->isAllowed());
    }

    /**
     * withPermission(true) on a decision with an empty trace leaves the held
     * step as its only entry.
     *
     * @return void
     */
    public function testWithPermissionHeldOnEmptyTrace(): void
    {
        $decision = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)->withPermission(true);

        self::assertEquals([new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD)], $decision->trace);
    }

    /**
     * withPermission(false) keeps the denial, its reason, stage and statements,
     * and appends a not-held step for the permission.
     *
     * @return void
     */
    public function testWithPermissionNotHeldKeepsTheDenial(): void
    {
        $statements = [new StatementReference('p', 0)];
        $entry      = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, $statements[0]);
        $original   = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, $statements, [$entry]);

        $decision = $original->withPermission(false);

        self::assertSame(DecisionEffect::DENY, $decision->effect);
        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::NO_MATCH, $decision->reason);
        self::assertSame(DecisionStage::IMPLICIT, $decision->stage);
        self::assertSame($statements, $decision->statements);
        self::assertCount(2, $decision->trace);
        self::assertSame($entry, $decision->trace[0]);
        self::assertEquals(new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD), $decision->trace[1]);
        self::assertSame([$entry], $original->trace);
    }

    /**
     * explain() renders an allow with the stage and every statement that
     * decided it, separated by commas.
     *
     * @return void
     */
    public function testExplainAllowWithStatements(): void
    {
        $decision = Decision::allow(DecisionStage::ALLOW, [new StatementReference('p', 0), new StatementReference('q', 1)]);

        self::assertSame('ALLOW at the allow stage by p#0, q#1.', $decision->explain());
    }

    /**
     * explain() renders an allow with no statements, such as a permission held,
     * without naming any.
     *
     * @return void
     */
    public function testExplainAllowWithoutStatements(): void
    {
        self::assertSame('ALLOW at the allow stage.', Decision::allow(DecisionStage::ALLOW)->explain());
    }

    /**
     * explain() renders a denial with no statements as its reason code and
     * label, then the stage.
     *
     * @return void
     */
    public function testExplainDenyWithoutStatements(): void
    {
        self::assertSame(
            'DENY (no_match: no statement or permission names it) at the implicit stage.',
            Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)->explain(),
        );
    }

    /**
     * explain() renders a denial with the statements that decided it.
     *
     * @return void
     */
    public function testExplainDenyWithStatements(): void
    {
        $decision = Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, [new StatementReference('p', 2)]);

        self::assertSame('DENY (explicit_deny: an applicable statement denies it) at the deny stage by p#2.', $decision->explain());
    }

    /**
     * explain() renders every reason with its code and label.
     *
     * @return void
     */
    public function testExplainCoversEveryReason(): void
    {
        foreach (DecisionReason::cases() as $reason) {
            self::assertSame(
                "DENY ({$reason->value}: {$reason->label()}) at the implicit stage.",
                Decision::deny($reason, DecisionStage::IMPLICIT)->explain(),
            );
        }
    }

    /**
     * explain() follows the first line with one indented line for each trace
     * entry, in order.
     *
     * @return void
     */
    public function testExplainIncludesTraceLines(): void
    {
        $p0       = new StatementReference('p', 0);
        $p1       = new StatementReference('p', 1);
        $decision = Decision::allow(DecisionStage::ALLOW, [$p1], [
            new TraceEntry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, $p0),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, $p1, ['owner' => true]),
        ]);

        self::assertSame(
            "ALLOW at the allow stage by p#1.\n"
            . "  [deny] p#0: not_applicable\n"
            . '  [allow] p#1: matched (owner held)',
            $decision->explain(),
        );
    }

    /**
     * explain() renders a permission step appended by withPermission() as the
     * last trace line.
     *
     * @return void
     */
    public function testExplainIncludesPermissionStep(): void
    {
        $decision = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], [
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, new StatementReference('p', 0)),
        ])->withPermission(false);

        self::assertSame(
            "DENY (no_match: no statement or permission names it) at the implicit stage.\n"
            . "  [allow] p#0: not_applicable\n"
            . '  [allow] permission: not_held',
            $decision->explain(),
        );
    }
}
