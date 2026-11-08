<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\NestedGrantException;

/**
 * Unit tests for `NestedGrantException`, a widening grant made inside another
 * management call's work.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NestedGrantException::class)]
final class NestedGrantExceptionTest extends TestCase
{
    /**
     * The exception is a logic error saying how to make the grant instead.
     *
     * @return void
     */
    public function testTheMessageSaysHowToMakeTheGrant(): void
    {
        $exception = new NestedGrantException;

        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertSame(
            'A grant that widens an identity\'s scope cannot be made inside another management call, after it may have taken locks; '
            . 'make it as a call of its own, before any call that takes the package\'s locks.',
            $exception->getMessage(),
        );
    }
}
