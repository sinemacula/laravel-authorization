<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews\Support;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Support\PageRead;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewPosition;

/**
 * Unit tests for one page of a review as it was read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PageRead::class)]
final class PageReadTest extends TestCase
{
    /**
     * It keeps its rows, where the next page starts, its completeness and its
     * instant.
     *
     * @return void
     */
    public function testItKeepsWhatWasRead(): void
    {
        $at   = new CarbonImmutable('2030-01-01 00:00:00', 'UTC');
        $next = new ReviewPosition($at, [0]);
        $page = new PageRead([], $next, false, $at);

        self::assertSame([[], $next, false, $at], [$page->rows, $page->next, $page->isComplete, $page->at]);
        self::assertNull((new PageRead([], null, true, $at))->next);
    }

    /**
     * It covers more than the stored grants unless a review filtered by an
     * action says it covers only them.
     *
     * @return void
     */
    public function testItSaysWhetherItCoversOnlyTheStoredGrants(): void
    {
        $at = new CarbonImmutable('2030-01-01 00:00:00', 'UTC');

        self::assertFalse((new PageRead([], null, true, $at))->isStoredInventoryOnly);
        self::assertTrue((new PageRead([], null, true, $at, true))->isStoredInventoryOnly);
    }
}
