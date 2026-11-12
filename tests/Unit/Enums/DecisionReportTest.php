<?php

declare(strict_types = 1);

namespace Tests\Unit\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport;

/**
 * Unit tests for the enum naming why a decision event was reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionReport::class)]
final class DecisionReportTest extends TestCase
{
    /**
     * The cases are declared in their order of precedence, the most specific
     * first: break-glass, preview, insufficient authentication, denial,
     * sensitive action, then any allow.
     *
     * @return void
     */
    public function testTheCasesAreInTheirOrderOfPrecedence(): void
    {
        self::assertSame([
            DecisionReport::BREAK_GLASS,
            DecisionReport::PREVIEW,
            DecisionReport::INSUFFICIENT_AUTHENTICATION,
            DecisionReport::DENIAL,
            DecisionReport::SENSITIVE_ACTION,
            DecisionReport::ALL_ALLOWS,
        ], DecisionReport::cases());
    }

    /**
     * Every case carries its documented backing value.
     *
     * @return void
     */
    public function testBackingValues(): void
    {
        self::assertSame(
            ['break_glass', 'preview', 'insufficient_authentication', 'denial', 'sensitive_action', 'all_allows'],
            \array_map(static fn (DecisionReport $report): string => $report->value, DecisionReport::cases()),
        );
        self::assertNull(DecisionReport::tryFrom('allow'));
    }
}
