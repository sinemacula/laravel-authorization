<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;

/**
 * Unit tests for what the structural check found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigFindings::class)]
final class ConfigFindingsTest extends TestCase
{
    /**
     * Findings are refused by a refusal alone, and incomplete by an unforeseen
     * failure alone; a skipped check is neither.
     *
     * @return void
     */
    public function testRefusedAndIncompleteAreToldApart(): void
    {
        $refusal  = new ConfigIssue('authorization.a', IssueCode::UNKNOWN_KEY);
        $skipped  = ConfigIssue::skipped('authorization.b', 'authorization');
        $internal = ConfigIssue::internal('authorization.c', new \RuntimeException);

        self::assertFalse((new ConfigFindings([], []))->isRefused());
        self::assertFalse((new ConfigFindings([$skipped], []))->isRefused());
        self::assertFalse((new ConfigFindings([$skipped], []))->isIncomplete());
        self::assertTrue((new ConfigFindings([$skipped, $refusal], []))->isRefused());
        self::assertFalse((new ConfigFindings([$refusal], []))->isIncomplete());
        self::assertTrue((new ConfigFindings([$internal], []))->isIncomplete());
        self::assertFalse((new ConfigFindings([$internal], []))->isRefused());
    }
}
