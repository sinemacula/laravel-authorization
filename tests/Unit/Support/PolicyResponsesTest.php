<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Container\Container;
use Illuminate\Contracts\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;
use SineMacula\Laravel\Authorization\Support\Messages;
use SineMacula\Laravel\Authorization\Support\PolicyResponses;

/**
 * Unit tests for `PolicyResponses`, which turns a decision into the response a
 * Laravel policy method returns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PolicyResponses::class)]
final class PolicyResponsesTest extends TestCase
{
    /**
     * Tear down Mockery instances and forget any container a test set after
     * every test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();
        Container::setInstance(null);

        parent::tearDown();
    }

    /**
     * An allowed decision is an allow, with no message and no code, and asks
     * the translator nothing.
     *
     * @return void
     */
    public function testAnAllowIsAnAllowResponse(): void
    {
        $translator = \Mockery::mock(Translator::class);
        $translator->shouldNotReceive('get');

        $response = PolicyResponses::of(Decision::allow(DecisionStage::ALLOW), $translator);

        self::assertTrue($response->allowed());
        self::assertNull($response->message());
        self::assertNull($response->code());
    }

    /**
     * Return every reason a decision can be denied with.
     *
     * @return iterable<string, array{\SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason}>
     */
    public static function reasons(): iterable
    {
        foreach (DecisionReason::cases() as $reason) {
            yield $reason->value => [$reason];
        }
    }

    /**
     * A denial carries its reason code and, whatever the reason, the generic
     * `denied` line.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @return void
     */
    #[DataProvider('reasons')]
    public function testADenialCarriesItsCodeAndTheGenericLine(DecisionReason $reason): void
    {
        $translator = \Mockery::mock(Translator::class);
        $translator->shouldReceive('get')->once()->with('authorization::authorization.denied')->andReturn('Refused.');

        $response = PolicyResponses::of(Decision::deny($reason, DecisionStage::DENY), $translator);

        self::assertTrue($response->denied());
        self::assertSame($reason->value, $response->code());
        self::assertSame('Refused.', $response->message());
    }

    /**
     * An insufficient authentication denial keeps its own code, carries the
     * generic line and carries no requirement.
     *
     * @return void
     */
    public function testAnInsufficientAuthenticationDenialKeepsItsCode(): void
    {
        $translator = \Mockery::mock(Translator::class);
        $translator->shouldReceive('get')->with(Messages::DENIED)->andReturn('Refused.');

        $requirement = new UnmetRequirement(new AuthenticationRequirement(['multifactor' => 900]), ['multifactor']);
        $response    = PolicyResponses::of(Decision::insufficientAuthentication(DecisionStage::ALLOW, [new StatementReference('step-up', 0)], [$requirement]), $translator);

        self::assertTrue($response->denied());
        self::assertSame('insufficient_authentication', $response->code());
        self::assertSame('Refused.', $response->message());
        self::assertStringNotContainsString('multifactor', \serialize($response->toArray()));
    }

    /**
     * Without a translator line the message is left to Laravel: a translator
     * that returns the key, or anything but a string, words nothing.
     *
     * @return void
     */
    public function testAnUntranslatedOrNonStringLineLeavesNoMessage(): void
    {
        $translator = \Mockery::mock(Translator::class);
        $translator->shouldReceive('get')->with(Messages::DENIED)->andReturn(Messages::DENIED, ['nested' => 'line']);

        $decision = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);

        self::assertNull(PolicyResponses::of($decision, $translator)->message());
        self::assertNull(PolicyResponses::of($decision, $translator)->message());
        self::assertSame('no_match', PolicyResponses::of($decision, $translator)->code());
    }

    /**
     * Without a translator given, the container's is used, and without one
     * bound the denial still carries its code.
     *
     * @return void
     */
    public function testTheContainersTranslatorIsTheDefault(): void
    {
        $decision = Decision::deny(DecisionReason::BOUNDARY, DecisionStage::BOUNDARY);

        Container::setInstance(new Container);

        self::assertNull(PolicyResponses::of($decision)->message());
        self::assertSame('boundary', PolicyResponses::of($decision)->code());

        $translator = \Mockery::mock(Translator::class);
        $translator->shouldReceive('get')->with(Messages::DENIED)->andReturn('Out of bounds.');

        $container = new Container;
        $container->instance(Translator::class, $translator);
        Container::setInstance($container);

        self::assertSame('Out of bounds.', PolicyResponses::of($decision)->message());
    }

    /**
     * A translator given to it is used rather than the container's.
     *
     * @return void
     */
    public function testAGivenTranslatorTakesPrecedenceOverTheContainers(): void
    {
        $decision = Decision::deny(DecisionReason::BOUNDARY, DecisionStage::BOUNDARY);

        $bound = \Mockery::mock(Translator::class);
        $bound->shouldNotReceive('get');

        $container = new Container;
        $container->instance(Translator::class, $bound);
        Container::setInstance($container);

        $given = \Mockery::mock(Translator::class);
        $given->shouldReceive('get')->once()->with(Messages::DENIED)->andReturn('Explicit line.');

        self::assertSame('Explicit line.', PolicyResponses::of($decision, $given)->message());
    }
}
