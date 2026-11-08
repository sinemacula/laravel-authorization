<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\GrantRefusedException;

/**
 * Unit tests for `GrantRefusedException`, a grant hook's refusal of a grant
 * that widens an identity's scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantRefusedException::class)]
final class GrantRefusedExceptionTest extends TestCase
{
    /**
     * The refusal is a runtime exception, never a decision of the package's,
     * with a default message, or the hook's own and its cause.
     *
     * @return void
     */
    public function testTheRefusalIsTheHooksOwn(): void
    {
        $cause   = new \RuntimeException('The provider refused.');
        $refusal = new GrantRefusedException('Not in this tenant.', $cause);

        self::assertInstanceOf(\RuntimeException::class, $refusal);
        self::assertNotInstanceOf(AuthorizationException::class, $refusal);
        self::assertSame('Not in this tenant.', $refusal->getMessage());
        self::assertSame($cause, $refusal->getPrevious());
        self::assertSame(0, $refusal->getCode());
        self::assertSame('A grant hook refused the grant.', (new GrantRefusedException)->getMessage());
        self::assertNull((new GrantRefusedException)->getPrevious());
    }
}
