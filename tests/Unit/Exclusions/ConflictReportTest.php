<?php

declare(strict_types = 1);

namespace Tests\Unit\Exclusions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exclusions\ConflictReport;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionConflict;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `ConflictReport`: who holds both roles of a pair.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConflictReport::class)]
final class ConflictReportTest extends TestCase
{
    /**
     * A report with no conflict is empty and holds no one, complete unless said
     * otherwise.
     *
     * @return void
     */
    public function testAReportWithNoConflictIsEmpty(): void
    {
        $role     = new Reference('role', 'a');
        $excluded = new Reference('role', 'b');
        $report   = new ConflictReport($role, $excluded);

        self::assertSame([$role, $excluded, []], [$report->role, $report->excludedRole, $report->conflicts]);
        self::assertTrue($report->isEmpty());
        self::assertTrue($report->isComplete);
        self::assertSame([], $report->holders());
        self::assertFalse((new ConflictReport($role, $excluded, [], false))->isComplete);
    }

    /**
     * A report with conflicts lists each holder once, in its order, whatever
     * number of conflicts it has.
     *
     * @return void
     */
    public function testListsEachHolderOnce(): void
    {
        $one   = new Reference('user', '1');
        $other = new Reference('member', '1');
        $route = new ExclusionRoute($one, new Reference('role', 'a'), [new Reference('role', 'a')], GrantScope::platform(), GrantScope::platform());

        $report = new ConflictReport(new Reference('role', 'a'), new Reference('role', 'b'), [
            new ExclusionConflict($one, null, $route, $route),
            new ExclusionConflict($other, $one, $route, $route),
            new ExclusionConflict($one, null, $route, $route),
        ]);

        self::assertFalse($report->isEmpty());
        self::assertSame([$one, $other], $report->holders());
    }
}
