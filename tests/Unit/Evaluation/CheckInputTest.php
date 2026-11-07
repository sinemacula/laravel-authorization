<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;

/**
 * Unit tests for `CheckInput`, one check of a bulk check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CheckInput::class)]
final class CheckInputTest extends TestCase
{
    /**
     * A check holds the action, the resource and the context it is given, and
     * names no resource and passes no context by default.
     *
     * @return void
     */
    public function testACheckHoldsWhatItIsGiven(): void
    {
        $resource = ['posts', '7'];
        $check    = new CheckInput('posts:read', $resource, ['flag' => 'on']);
        $bare     = new CheckInput('posts:create');

        self::assertSame('posts:read', $check->action);
        self::assertSame($resource, $check->resource);
        self::assertSame(['flag' => 'on'], $check->context);
        self::assertNull($bare->resource);
        self::assertSame([], $bare->context);
    }
}
