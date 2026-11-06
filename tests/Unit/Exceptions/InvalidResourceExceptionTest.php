<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidResourceException;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Unit tests for the refusal of a value that names no resource a policy can be
 * attached to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidResourceException::class)]
final class InvalidResourceExceptionTest extends TestCase
{
    /**
     * The message names the kind of value refused.
     *
     * @return void
     */
    public function testNamesTheValueRefused(): void
    {
        $exception = new InvalidResourceException(new ResourceReference('opaque'));

        self::assertInstanceOf(\InvalidArgumentException::class, $exception);
        self::assertSame('A resource policy is attached to a record or a resource type, not ' . ResourceReference::class . '.', $exception->getMessage());
        self::assertSame('A resource policy is attached to a record or a resource type, not null.', (new InvalidResourceException(null))->getMessage());
        self::assertSame('A resource policy is attached to a record or a resource type, not string.', (new InvalidResourceException(''))->getMessage());
    }
}
