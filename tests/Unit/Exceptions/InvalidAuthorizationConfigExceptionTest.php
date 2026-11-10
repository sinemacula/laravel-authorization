<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
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

    /**
     * The refusal carries a stable code, what the setting expects and the type
     * found, none of which holds the value; a refusal that states none is an
     * invalid value, expecting and finding nothing stated.
     *
     * @return void
     */
    public function testTheRefusalIsStructured(): void
    {
        $refusal = new InvalidAuthorizationConfigException('authorization.x', 'got \'secret\'.', IssueCode::OUT_OF_RANGE, 'a whole number of at least 1', 'int');
        $plain   = new InvalidAuthorizationConfigException('authorization.x', 'no.');

        self::assertSame(IssueCode::OUT_OF_RANGE, $refusal->getIssue());
        self::assertSame('a whole number of at least 1', $refusal->getExpected());
        self::assertSame('int', $refusal->getGotType());
        self::assertSame(IssueCode::INVALID_VALUE, $plain->getIssue());
        self::assertNull($plain->getExpected());
        self::assertNull($plain->getGotType());
    }
}
