<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\GrantHookRecursionException;

/**
 * Unit tests for `GrantHookRecursionException`, a management service called
 * while a grant hook runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantHookRecursionException::class)]
final class GrantHookRecursionExceptionTest extends TestCase
{
    /**
     * The exception is a logic error saying a hook may only refuse.
     *
     * @return void
     */
    public function testTheMessageSaysAHookMayOnlyRefuse(): void
    {
        $exception = new GrantHookRecursionException;

        self::assertInstanceOf(\LogicException::class, $exception);
        self::assertSame('A grant hook may not call a management service of the authorization package; a hook may only refuse the grant by throwing.', $exception->getMessage());
    }
}
