<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\ReportParts;

/**
 * Unit tests for reading each part of the configuration report on its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ReportParts::class)]
final class ReportPartsTest extends TestCase
{
    /**
     * A part read is returned; one that throws is replaced by its fallback and
     * recorded as internal, by its class alone, naming the part.
     *
     * @return void
     */
    public function testAPartThatThrowsFallsBack(): void
    {
        $parts = new ReportParts;

        self::assertSame(['read'], $parts->read('seams', static fn (): array => ['read'], []));
        self::assertSame([], (new ReportParts)->failures());
        self::assertSame(['fallback'], $parts->read('settings', static fn (): never => throw new \LogicException('secret'), ['fallback']));

        $failures = $parts->failures();

        self::assertCount(1, $failures);
        self::assertSame('report.settings', $failures[0]->path);
        self::assertSame(\LogicException::class, $failures[0]->exception);
        self::assertSame('internal', $failures[0]->kind());
    }
}
