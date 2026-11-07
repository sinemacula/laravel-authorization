<?php

declare(strict_types = 1);

namespace Tests\Unit\Query;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\KeyTarget;

/**
 * Unit tests for which records of a type a resource pattern names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyTarget::class)]
final class KeyTargetTest extends TestCase
{
    /**
     * Each target says what it names, and only every record's is all and only
     * no record's is none.
     *
     * @return void
     */
    public function testEachTargetSaysWhatItNames(): void
    {
        $all    = KeyTarget::all();
        $none   = KeyTarget::none();
        $equals = KeyTarget::equals('5');
        $prefix = KeyTarget::prefix('x:*', true);

        self::assertSame([KeyTarget::ALL, '', false, true, false], [$all->kind, $all->value, $all->isValueExcluded, $all->isAll(), $all->isNone()]);
        self::assertSame([KeyTarget::NONE, '', false, false, true], [$none->kind, $none->value, $none->isValueExcluded, $none->isAll(), $none->isNone()]);
        self::assertSame([KeyTarget::EQUALS, '5', false, false, false], [$equals->kind, $equals->value, $equals->isValueExcluded, $equals->isAll(), $equals->isNone()]);
        self::assertSame([KeyTarget::PREFIX, 'x:*', true, false, false], [$prefix->kind, $prefix->value, $prefix->isValueExcluded, $prefix->isAll(), $prefix->isNone()]);
        self::assertFalse(KeyTarget::prefix('a', false)->isValueExcluded);
    }
}
