<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewPage;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for one page of a paged review.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReviewPage::class)]
final class ReviewPageTest extends TestCase
{
    /**
     * It keeps its rows, cursor, instant and completeness, is the last page
     * only without a cursor, and gives each row in its versioned shape.
     *
     * @return void
     */
    public function testItKeepsItsRowsAndSaysWhetherItIsTheLast(): void
    {
        $at   = new CarbonImmutable('2030-01-01 00:00:00', 'UTC');
        $rows = [self::row('a'), self::row('b')];
        $page = new ReviewPage($rows, 'cursor', $at, false);

        self::assertSame([$rows, 'cursor', $at, false], [$page->rows, $page->nextCursor, $page->reviewedAt, $page->isComplete]);
        self::assertFalse($page->isLast());
        self::assertSame(['a', 'b'], \array_column($page->toArray(), 'row_key'));

        $last = new ReviewPage([], null, $at, true);

        self::assertTrue($last->isLast());
        self::assertSame([], $last->toArray());
    }

    /**
     * Return a row with the key.
     *
     * @param  string  $key
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewRow
     */
    private static function row(string $key): ReviewRow
    {
        $reference = new Reference('user', 'u');

        return new ReviewRow(
            $key,
            $reference,
            $reference,
            new Reference('role', 'r'),
            SourceKind::ROLE_GRANT,
            's',
            null,
            null,
            [],
            [],
            ['created_at' => null, 'updated_at' => null, 'expires_at' => null, 'route_expires_at' => null],
            null,
            GrantState::LIVE,
        );
    }
}
