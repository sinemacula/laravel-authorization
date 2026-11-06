<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use Illuminate\Auth\Access\AuthorizationException as LaravelAuthorizationException;
use Illuminate\Contracts\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Support\Messages;

/**
 * Unit tests for `AuthorizationException`, the denial `authorize()` and the
 * route middleware raise.
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
        $exception = new AuthorizationException(DecisionReason::NO_MATCH);

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
        $exception = new AuthorizationException(DecisionReason::NO_MATCH, 'Action non autorisée.');

        self::assertSame('Action non autorisée.', $exception->getMessage());
    }

    /**
     * Without a message, the exception keeps Laravel's English default.
     *
     * @return void
     */
    public function testDefaultsToLaravelsMessage(): void
    {
        $exception = new AuthorizationException(DecisionReason::NO_MATCH);

        self::assertSame('This action is unauthorized.', $exception->getMessage());
    }

    /**
     * `translated()` words the message with the translator's generic `denied`
     * line, whatever the reason, and keeps the reason code.
     *
     * @return void
     */
    public function testTranslatedUsesTheGenericLineForEveryReason(): void
    {
        $translator = self::createStub(Translator::class);
        $translator->method('get')->willReturnMap([[Messages::DENIED, [], null, 'Action non autorisée.']]);

        foreach (DecisionReason::cases() as $reason) {
            $denial = AuthorizationException::translated($reason, $translator);

            self::assertSame('Action non autorisée.', $denial->getMessage());
            self::assertSame($reason, $denial->getReason());
        }
    }

    /**
     * Without a translator, or when the translator has no line for the key (it
     * answers with the key) or answers with something other than a line, the
     * message is Laravel's English default.
     *
     * @return void
     */
    public function testTranslatedFallsBackToLaravelsMessage(): void
    {
        $missing = self::createStub(Translator::class);
        $missing->method('get')->willReturn(Messages::DENIED);

        $group = self::createStub(Translator::class);
        $group->method('get')->willReturn(['denied' => 'Denied.']);

        foreach ([null, $missing, $group] as $translator) {
            self::assertSame('This action is unauthorized.', AuthorizationException::translated(DecisionReason::NO_MATCH, $translator)->getMessage());
        }
    }
}
