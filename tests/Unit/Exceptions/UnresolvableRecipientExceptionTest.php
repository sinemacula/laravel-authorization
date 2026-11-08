<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\UnresolvableRecipientException;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `UnresolvableRecipientException`, a grant refused because the
 * identity behind its grantee cannot be resolved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UnresolvableRecipientException::class)]
final class UnresolvableRecipientExceptionTest extends TestCase
{
    /**
     * The exception carries the grantee and its cause, and names only the
     * grantee's type.
     *
     * @return void
     */
    public function testTheMessageNamesTheGranteesTypeAlone(): void
    {
        $grantee   = new Reference('principals', 'secret-key');
        $cause     = new \RuntimeException('The resolver failed.');
        $exception = new UnresolvableRecipientException($grantee, $cause);

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertSame($grantee, $exception->grantee);
        self::assertSame($cause, $exception->getPrevious());
        self::assertSame(0, $exception->getCode());
        self::assertSame('The identity behind a grantee of type [principals] cannot be resolved, so a grant that may widen its scope is refused.', $exception->getMessage());
        self::assertNull((new UnresolvableRecipientException($grantee))->getPrevious());
    }
}
