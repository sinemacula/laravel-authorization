<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;

/**
 * Unit tests for `DependencyChangedException`, the conflict of a delegated
 * operation whose decisions read something that changed before the write.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DependencyChangedException::class)]
final class DependencyChangedExceptionTest extends TestCase
{
    /**
     * Rows that changed are named by their table, a moved tree and a widening
     * no grant hook was run for as such, keeping the conflict an earlier try
     * failed with when given; each is a runtime exception, and only the
     * widening is one.
     *
     * @return void
     */
    public function testTheMessagesNameWhatChanged(): void
    {
        $rows = DependencyChangedException::rows('roles');
        $tree = DependencyChangedException::tree();

        self::assertInstanceOf(\RuntimeException::class, $rows);
        self::assertSame('The rows of [roles] a delegated decision read changed before the write.', $rows->getMessage());
        self::assertSame('The tenant tree moved after a delegated decision read it, before the write.', $tree->getMessage());
        self::assertSame('A grant now widens an identity\'s scope although its grant hooks were not run for it.', DependencyChangedException::widening()->getMessage());
        self::assertTrue(DependencyChangedException::widening()->isWidening());
        self::assertFalse($rows->isWidening());
        self::assertFalse($tree->isWidening());
        self::assertNull(DependencyChangedException::widening()->getPrevious());
        self::assertSame($rows, DependencyChangedException::widening($rows)->getPrevious());
        self::assertNull($rows->getPrevious());
    }
}
