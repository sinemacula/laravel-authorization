<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;

/**
 * Unit tests for the stable codes of the issues the configuration check lists.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IssueCode::class)]
final class IssueCodeTest extends TestCase
{
    /**
     * The codes are part of the report's versioned shape, so they never change.
     *
     * @return void
     */
    public function testTheCodesAreStable(): void
    {
        self::assertSame([
            'unknown_key', 'invalid_type', 'out_of_range', 'unknown_class', 'not_implemented', 'unknown_name',
            'duplicate', 'required', 'invalid_value', 'invalid_catalogue', 'skipped', 'internal',
        ], \array_map(static fn (IssueCode $code): string => $code->value, IssueCode::cases()));
    }

    /**
     * Every code refuses the configuration but a skipped check and an
     * unforeseen failure.
     *
     * @return void
     */
    public function testEveryCodeButSkippedAndInternalIsARefusal(): void
    {
        foreach (IssueCode::cases() as $code) {
            self::assertSame(!\in_array($code, [IssueCode::SKIPPED, IssueCode::INTERNAL], true), $code->isRefusal(), $code->value);
        }
    }
}
