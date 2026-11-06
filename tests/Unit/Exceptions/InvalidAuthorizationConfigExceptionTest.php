<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Unit tests for `InvalidAuthorizationConfigException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidAuthorizationConfigException::class)]
final class InvalidAuthorizationConfigExceptionTest extends TestCase
{
    /**
     * The message names the config key at fault and the reason, both of which
     * the accessors return.
     *
     * @return void
     */
    public function testCarriesTheConfigKeyAndTheReason(): void
    {
        $exception = new InvalidAuthorizationConfigException('authorization.gate.enabled', 'expected true or false, got string.');

        self::assertSame('Invalid authorization config at \'authorization.gate.enabled\': expected true or false, got string.', $exception->getMessage());
        self::assertSame('authorization.gate.enabled', $exception->getConfigKey());
        self::assertSame('expected true or false, got string.', $exception->getReason());
        self::assertSame(500, $exception->getCode());
    }
}
