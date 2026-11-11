<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigurationReport;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\ReportStatus;
use SineMacula\Laravel\Authorization\Diagnostics\TableReader;

/**
 * Unit tests for the configuration report's status and versioned shape.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigurationReport::class)]
final class ConfigurationReportTest extends TestCase
{
    /**
     * No issue passes, a skipped check alone passes, an unforeseen failure
     * leaves the report incomplete, and a refusal wins over it.
     *
     * @return void
     */
    public function testARefusalWinsOverAnIncompleteReport(): void
    {
        $refusal  = new ConfigIssue('authorization.a', IssueCode::OUT_OF_RANGE);
        $internal = ConfigIssue::internal('report.seams', new \RuntimeException);

        self::assertSame(ReportStatus::PASSED, ConfigurationReport::statusOf([]));
        self::assertSame(ReportStatus::PASSED, ConfigurationReport::statusOf([ConfigIssue::skipped('authorization.b', 'authorization.a')]));
        self::assertSame(ReportStatus::INCOMPLETE, ConfigurationReport::statusOf([$internal]));
        self::assertSame(ReportStatus::REFUSED, ConfigurationReport::statusOf([$internal, $refusal]));
    }

    /**
     * The report's shape names its version first, then its status, then each
     * part, with the status the issues give.
     *
     * @return void
     */
    public function testTheShapeIsVersioned(): void
    {
        $tables = ['prefix' => 'app_', 'names' => [['key' => 'roles', 'name' => 'app_roles', 'explicit' => false]]];
        $report = new ConfigurationReport([], [], [], ['database' => []], [], [new ConfigIssue('authorization.a', IssueCode::DUPLICATE)], $tables);

        self::assertSame(TableReader::UNREAD, (new ConfigurationReport([], [], [], [], [], []))->tables);
        self::assertSame([
            'version'      => 1,
            'status'       => 'refused',
            'settings'     => [],
            'tables'       => $tables,
            'seams'        => [],
            'grant_hooks'  => [],
            'connection'   => ['database' => []],
            'integrations' => [],
            'issues'       => [[
                'path'       => 'authorization.a',
                'code'       => 'duplicate',
                'kind'       => 'refusal',
                'expected'   => null,
                'got_type'   => null,
                'depends_on' => null,
                'exception'  => null,
            ]],
        ], $report->toArray());
    }
}
