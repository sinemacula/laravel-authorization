<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed;

/**
 * Unit tests for the failure of an attribute provider, which aborts the check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttributeProviderFailed::class)]
final class AttributeProviderFailedTest extends TestCase
{
    /**
     * The failure names the provider and the namespace, keeps the original as
     * the previous exception and copies nothing of its message.
     *
     * @return void
     */
    public function testNamesTheProviderAndNamespaceOnly(): void
    {
        $previous  = new \RuntimeException('status of owner@example.com unavailable');
        $exception = new AttributeProviderFailed('App\PostAttributes', 'resource', $previous);

        self::assertSame('Attribute provider \'App\PostAttributes\' failed to supply the \'resource\' namespace, so the check was aborted.', $exception->getMessage());
        self::assertSame('App\PostAttributes', $exception->getProvider());
        self::assertSame('resource', $exception->getNamespace());
        self::assertSame($previous, $exception->getPrevious());
        self::assertSame(0, $exception->getCode());
        self::assertInstanceOf(\RuntimeException::class, $exception);
    }
}
