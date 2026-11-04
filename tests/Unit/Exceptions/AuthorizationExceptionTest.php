<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use Illuminate\Auth\Access\AuthorizationException as LaravelAuthorizationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;

/**
 * Unit tests for `AuthorizationException`, the denial `authorize()` raises.
 *
 * Pins that it is Laravel's authorization exception, so the handler renders a
 * `403`, and that it carries the decision's reason code and the message it is
 * given, and nothing that identifies the action, the resource or a policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationException::class)]
final class AuthorizationExceptionTest extends TestCase
{
    /**
     * The exception is Laravel's authorization exception, without a status of
     * its own, so Laravel's handler maps it to its `403` response.
     *
     * @return void
     */
    public function testIsLaravelsAuthorizationException(): void
    {
        $exception = new AuthorizationException(DecisionReason::IMPLICIT_DENY);

        self::assertInstanceOf(LaravelAuthorizationException::class, $exception);
        self::assertFalse($exception->hasStatus());
        self::assertSame(403, $exception->getCode());
    }

    /**
     * The exception carries the reason code of the decision it was raised for.
     *
     * @return void
     */
    public function testCarriesTheReasonCode(): void
    {
        $exception = new AuthorizationException(DecisionReason::EXPLICIT_DENY);

        self::assertSame(DecisionReason::EXPLICIT_DENY, $exception->getReason());
    }

    /**
     * The exception's message is the one it is given, verbatim.
     *
     * @return void
     */
    public function testUsesTheGivenMessage(): void
    {
        $exception = new AuthorizationException(DecisionReason::IMPLICIT_DENY, 'Action non autorisée.');

        self::assertSame('Action non autorisée.', $exception->getMessage());
    }

    /**
     * Without a message, the exception keeps Laravel's English default.
     *
     * @return void
     */
    public function testDefaultsToLaravelsMessage(): void
    {
        $exception = new AuthorizationException(DecisionReason::IMPLICIT_DENY);

        self::assertSame('This action is unauthorized.', $exception->getMessage());
    }

    /**
     * The translation key names the `denied` line of the package's
     * `authorization` language file.
     *
     * @return void
     */
    public function testMessageKeyNamesThePackageLine(): void
    {
        self::assertSame('authorization::authorization.denied', AuthorizationException::MESSAGE_KEY);
    }
}
