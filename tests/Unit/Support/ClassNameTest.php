<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\ClassName;

/**
 * Unit tests for comparing class names as PHP does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClassName::class)]
final class ClassNameTest extends TestCase
{
    /**
     * Names differing only by case or a leading backslash name one class;
     * others do not.
     *
     * @return void
     */
    public function testNamesOfOneClassCompareEqual(): void
    {
        self::assertSame('app\tree', ClassName::normalise('\App\Tree'));
        self::assertTrue(ClassName::areSame('App\Tree', '\App\Tree'));
        self::assertTrue(ClassName::areSame('APP\TREE', 'app\tree'));
        self::assertFalse(ClassName::areSame('App\Tree', 'App\Trees'));
        self::assertFalse(ClassName::areSame('App\Tree', '\\\App\Tree\\'));
    }
}
