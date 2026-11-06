<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;

/**
 * Unit tests for the trace entry value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(TraceEntry::class)]
final class TraceEntryTest extends TestCase
{
    /**
     * The constructor stores the stage and the outcome, and defaults to no
     * statement and no conditions.
     *
     * @return void
     */
    public function testConstructorDefaultsStatementAndConditions(): void
    {
        $entry = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD);

        self::assertSame(DecisionStage::ALLOW, $entry->stage);
        self::assertSame(TraceOutcome::HELD, $entry->outcome);
        self::assertNull($entry->statement);
        self::assertSame([], $entry->conditions);
        self::assertNull($entry->boundary);
    }

    /**
     * The constructor stores the supplied statement and conditions.
     *
     * @return void
     */
    public function testConstructorStoresStatementAndConditions(): void
    {
        $statement = new StatementReference('p', 1);
        $entry     = new TraceEntry(DecisionStage::DENY, TraceOutcome::CONDITION_FAILED, $statement, ['region' => false]);

        self::assertSame(DecisionStage::DENY, $entry->stage);
        self::assertSame(TraceOutcome::CONDITION_FAILED, $entry->outcome);
        self::assertSame($statement, $entry->statement);
        self::assertSame(['region' => false], $entry->conditions);
    }

    /**
     * toString() names the permission when the step assessed no statement.
     *
     * @return void
     */
    public function testToStringWithoutStatementNamesThePermission(): void
    {
        self::assertSame('[allow] permission: held', (new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD))->toString());
        self::assertSame('[allow] permission: not_held', (new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD))->toString());
    }

    /**
     * toString() names the caps a cap stage weighs when it capped nothing.
     *
     * @return void
     */
    public function testToStringWithoutStatementNamesTheCapsOfACapStage(): void
    {
        self::assertSame('[guardrail] guardrails: uncapped', (new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::UNCAPPED))->toString());
        self::assertSame('[boundary] boundaries: uncapped', (new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::UNCAPPED))->toString());
        self::assertSame('[session] session caps: uncapped', (new TraceEntry(DecisionStage::SESSION, TraceOutcome::UNCAPPED))->toString());
    }

    /**
     * toString() names the boundary a step about no one statement is about,
     * such as one that refused the check.
     *
     * @return void
     */
    public function testToStringNamesTheBoundaryOfAStepAboutNoStatement(): void
    {
        $entry = new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::REFUSED, null, [], 'cap[7]');

        self::assertSame('cap[7]', $entry->boundary);
        self::assertSame('[boundary] cap[7]: refused', $entry->toString());
    }

    /**
     * toString() names the statement assessed before the boundary it belongs
     * to.
     *
     * @return void
     */
    public function testToStringNamesTheStatementBeforeTheBoundary(): void
    {
        $entry = new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::MATCHED, new StatementReference('cap', 0), [], 'cap');

        self::assertSame('[boundary] cap#0: matched', $entry->toString());
    }

    /**
     * toString() names the statement assessed, and adds nothing more when it
     * tested no condition.
     *
     * @return void
     */
    public function testToStringWithStatementAndNoConditions(): void
    {
        $entry = new TraceEntry(DecisionStage::DENY, TraceOutcome::NOT_APPLICABLE, new StatementReference('q', 2));

        self::assertSame('[deny] q#2: not_applicable', $entry->toString());
    }

    /**
     * toString() lists each condition key tested, in order, with whether it
     * held or failed.
     *
     * @return void
     */
    public function testToStringListsEveryCondition(): void
    {
        $entry = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::CONDITION_FAILED, new StatementReference('p', 0), ['owner' => true, 'region' => false]);

        self::assertSame('[allow] p#0: condition_failed (owner held, region failed)', $entry->toString());
    }

    /**
     * toString() lists a single condition without a separator.
     *
     * @return void
     */
    public function testToStringListsASingleCondition(): void
    {
        $entry = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, new StatementReference('p', 0), ['owner' => true]);

        self::assertSame('[allow] p#0: matched (owner held)', $entry->toString());
    }

    /**
     * toString() lists conditions on a permission step as well, after the
     * permission.
     *
     * @return void
     */
    public function testToStringListsConditionsWithoutStatement(): void
    {
        $entry = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD, null, ['scope' => false]);

        self::assertSame('[allow] permission: not_held (scope failed)', $entry->toString());
    }
}
