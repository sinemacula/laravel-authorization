<?php

declare(strict_types = 1);

namespace Tests\Unit\Reviews;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewResult;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for what an admitted review returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReviewResult::class)]
final class ReviewResultTest extends TestCase
{
    /**
     * It keeps its rows, truncation, completeness and instant, and gives each
     * row in its versioned shape, in order.
     *
     * @return void
     */
    public function testItGivesEachRowInItsShape(): void
    {
        $at     = new CarbonImmutable('2030-01-01 00:00:00', 'UTC');
        $rows   = [self::row('a'), self::row('b')];
        $result = new ReviewResult($rows, true, false, $at);

        self::assertSame([$rows, true, false, $at], [$result->rows, $result->isTruncated, $result->isComplete, $result->reviewedAt]);
        self::assertSame(['a', 'b'], \array_column($result->toArray(), 'row_key'));
        self::assertSame([], (new ReviewResult([], false, true, $at))->toArray());
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
