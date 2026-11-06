<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use Illuminate\Auth\Access\AuthorizationException as LaravelAuthorizationException;
use Illuminate\Contracts\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Authorization\Support\Messages;

/**
 * Unit tests for `InsufficientAuthenticationException`, the denial
 * `authorize()` raises for an `insufficient_authentication` decision.
 *
 * Pins that it is Laravel's authorization exception, so an unmapped one renders
 * a `403`, and that it carries the reason code and the candidate requirements
 * with their unmet parts, once each, and nothing else.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InsufficientAuthenticationException::class)]
final class InsufficientAuthenticationExceptionTest extends TestCase
{
    /**
     * The exception is Laravel's authorization exception, without a status of
     * its own, so Laravel's handler maps it to its `403` response.
     *
     * @return void
     */
    public function testIsLaravelsAuthorizationException(): void
    {
        $exception = new InsufficientAuthenticationException([]);

        self::assertInstanceOf(LaravelAuthorizationException::class, $exception);
        self::assertFalse($exception->hasStatus());
        self::assertSame(403, $exception->getCode());
    }

    /**
     * The exception carries the insufficient_authentication reason code and the
     * candidate requirements, in order.
     *
     * @return void
     */
    public function testCarriesTheReasonAndTheCandidates(): void
    {
        $candidates = self::candidates();
        $exception  = new InsufficientAuthenticationException($candidates);

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $exception->getReason());
        self::assertSame($candidates, $exception->requirements());
    }

    /**
     * A candidate given twice, with the same requirement and unmet parts, is
     * carried once; one with other unmet parts is another candidate.
     *
     * @return void
     */
    public function testCarriesEachCandidateOnce(): void
    {
        [$first, $second] = self::candidates();

        $twin    = new UnmetRequirement(new AuthenticationRequirement(['multifactor' => 900, 'phishing_resistant' => null]), ['multifactor']);
        $partial = new UnmetRequirement($first->requirement, ['multifactor', 'phishing_resistant']);

        self::assertSame([$first, $second, $partial], (new InsufficientAuthenticationException([$first, $twin, $second, $partial, $second]))->requirements());
    }

    /**
     * The exception holds the candidates alone: no policy, statement, trace or
     * proof is among its own properties.
     *
     * @return void
     */
    public function testHoldsNothingButTheCandidates(): void
    {
        $properties = \array_map(
            static fn (\ReflectionProperty $property): string => $property->getName(),
            (new \ReflectionClass(InsufficientAuthenticationException::class))->getProperties(),
        );

        self::assertSame(['requirements'], \array_values(\array_diff($properties, \array_map(
            static fn (\ReflectionProperty $property): string => $property->getName(),
            (new \ReflectionClass(LaravelAuthorizationException::class))->getProperties(),
        ))));
        self::assertSame([
            [
                'requirement' => ['multifactor' => ['max_age' => 900], 'phishing_resistant' => ['max_age' => null]],
                'unmet'       => ['multifactor'],
            ],
            [
                'requirement' => ['assurance_level' => ['max_age' => null, 'min' => 'aal2']],
                'unmet'       => ['assurance_level'],
            ],
        ], \array_map(static fn (UnmetRequirement $candidate): array => $candidate->toArray(), (new InsufficientAuthenticationException(self::candidates()))->requirements()));
    }

    /**
     * The message is the one it is given, and Laravel's English default without
     * one.
     *
     * @return void
     */
    public function testTheMessage(): void
    {
        self::assertSame('Authentification requise.', (new InsufficientAuthenticationException([], 'Authentification requise.'))->getMessage());
        self::assertSame('This action is unauthorized.', (new InsufficientAuthenticationException([]))->getMessage());
    }

    /**
     * `translated()` words the message with the translator's generic `denied`
     * line, as every denial's, keeping the candidates.
     *
     * @return void
     */
    public function testTranslatedUsesTheTranslatorsLine(): void
    {
        $translator = self::createStub(Translator::class);
        $translator->method('get')->willReturnMap([[Messages::DENIED, [], null, 'Action non autorisée.']]);

        $exception = InsufficientAuthenticationException::translated(self::candidates(), $translator);

        self::assertSame('Action non autorisée.', $exception->getMessage());
        self::assertSame(self::candidates()[0]->toArray(), $exception->requirements()[0]->toArray());
    }

    /**
     * Without a translator, or when the translator has no line for the key or
     * answers with something other than a line, the message is Laravel's
     * English default.
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
            self::assertSame('This action is unauthorized.', InsufficientAuthenticationException::translated([], $translator)->getMessage());
        }
    }

    /**
     * Return two candidate requirements.
     *
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement>
     */
    private static function candidates(): array
    {
        return [
            new UnmetRequirement(new AuthenticationRequirement(['multifactor' => 900, 'phishing_resistant' => null]), ['multifactor']),
            new UnmetRequirement(new AuthenticationRequirement(['assurance_level' => null], 'aal2'), ['assurance_level']),
        ];
    }
}
