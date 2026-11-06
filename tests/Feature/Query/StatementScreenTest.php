<?php

declare(strict_types = 1);

namespace Tests\Feature\Query;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PrincipalSelectors;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\Refusal;
use SineMacula\Laravel\Authorization\Query\StatementScreen;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the screen that tells whether the statements one class of
 * rows is decided from can be compiled.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(StatementScreen::class)]
final class StatementScreenTest extends TestCase
{
    /** @var string The type the screened query is about. */
    private const string TYPE = 'posts';

    /**
     * A statement a check would not weigh is never screened: one naming another
     * action, an allow of a resource policy not naming the subject, one of a
     * policy attached otherwise naming principals, and a guardrail's when the
     * check is exempt from them.
     *
     * @return void
     */
    public function testAStatementACheckWouldNotWeighIsNotScreened(): void
    {
        [$screen, $subject] = $this->screen();
        $record             = ['posts:1'];

        $sources = $this->sources($subject, [
            new Policy('other-action', [new Statement(PolicyEffect::DENY, ['posts:edit'], $record)]),
            (new Policy('shared', [new Statement(PolicyEffect::ALLOW, ['posts:view'], $record, principals: ['user:someone-else'])]))->withResource('posts:*'),
            new Policy('named', [new Statement(PolicyEffect::ALLOW, ['posts:view'], $record, principals: [$this->reference($subject)])]),
        ], null);

        self::assertSame([], $screen->screen($sources, 'posts:*'));
        self::assertSame([], $screen->refusals());
    }

    /**
     * Every statement a check would weigh is screened: a deny, a resource
     * policy's allow naming the subject, a guardrail's and a boundary's allows;
     * each refusal is kept once however often it is found.
     *
     * @return void
     */
    public function testEveryStatementACheckWouldWeighIsScreened(): void
    {
        [$screen, $subject] = $this->screen();
        $record             = ['posts:1'];
        $cap                = static fn (string $name): Policy => new Policy($name, [new Statement(PolicyEffect::ALLOW, ['*'], $record)]);

        $sources = $this->sources($subject, [
            new Policy('deny', [new Statement(PolicyEffect::DENY, ['posts:*'], $record)]),
            (new Policy('shared', [new Statement(PolicyEffect::ALLOW, ['posts:view'], $record, principals: [$this->reference($subject)])]))->withResource('posts:*'),
        ], [$cap('guardrail')], [$cap('boundary')]);

        self::assertCount(4, $screen->screen($sources, 'posts:*'));
        self::assertCount(4, $screen->screen($sources, 'posts:*'));
        $refusals = $screen->refusals();

        self::assertSame(['deny#0', 'shared#0 on "posts:*"', 'guardrail#0', 'boundary#0'], \array_map(static fn (Refusal $refusal): ?string => $refusal->statement, $refusals));
        self::assertSame(\array_fill(0, 4, RefusalReason::RESOURCE_PATTERN), \array_map(static fn (Refusal $refusal): RefusalReason => $refusal->reason, $refusals));
    }

    /**
     * A weighed statement naming another type, or a record of it, is refused
     * even though it covers no record of the type: only patterns covering every
     * record compile.
     *
     * @return void
     */
    public function testAnotherTypesPatternIsRefused(): void
    {
        [$screen, $subject] = $this->screen();

        $screen->screen($this->sources($subject, [new Policy('other', [
            new Statement(PolicyEffect::DENY, ['posts:view'], ['other:*']),
            new Statement(PolicyEffect::DENY, ['posts:view'], ['other:5']),
            new Statement(PolicyEffect::DENY, ['posts:view'], null, notResources: ['po*', 'x*']),
            new Statement(PolicyEffect::DENY, ['posts:view'], ['p*', 'posts:*', '*']),
        ])]), 'posts:*');

        self::assertSame(['other#0', 'other#1', 'other#2'], \array_map(static fn (Refusal $refusal): ?string => $refusal->statement, $screen->refusals()));
        self::assertSame(\array_fill(0, 3, RefusalReason::RESOURCE_PATTERN), \array_map(static fn (Refusal $refusal): RefusalReason => $refusal->reason, $screen->refusals()));
    }

    /**
     * The screen says a statement matches a pattern against the identifier only
     * when a pattern of a weighed statement resolves: not one whose reference
     * cannot be resolved or resolves to a NUL byte, and not one with no
     * pattern; neither is refused.
     *
     * @return void
     */
    public function testAPatternCountsOnlyWhenItResolves(): void
    {
        [$screen, $subject] = $this->screen();
        $unresolved         = $this->sources($subject, [new Policy('unresolved', [
            new Statement(PolicyEffect::DENY, ['posts:view'], ['${input.missing}:*', '${input.nul}']),
            new Statement(PolicyEffect::ALLOW, ['posts:view']),
        ])]);

        self::assertSame([], $screen->screen($unresolved, 'posts:*'));
        $typed   = $this->sources($subject, [new Policy('typed', [new Statement(PolicyEffect::ALLOW, ['posts:view'], ['${input.type}:*'])])]);
        $negated = $this->sources($subject, [new Policy('negated', [new Statement(PolicyEffect::DENY, ['posts:view'], null, notResources: ['posts:*'])])]);

        self::assertSame(['typed#0'], \array_map(static fn (StatementReference $reference): string => $reference->toString(), $screen->screen($typed, 'posts:*')));
        self::assertCount(1, $screen->screen($negated, 'posts:*'));
        self::assertSame([], $screen->refusals());
    }

    /**
     * A weighed statement that cannot be evaluated is refused; one whose
     * resources cover no record of the type is not, since a check never reaches
     * its conditions.
     *
     * @return void
     */
    public function testAnInvalidStatementIsRefusedWhenItsConditionsAreReached(): void
    {
        [$screen, $subject] = $this->screen();
        $broken             = ['no_such_operator' => ['input.x' => 1]];

        $screen->screen($this->sources($subject, [new Policy('broken', [
            new Statement(PolicyEffect::ALLOW, ['posts:view'], null, $broken, notResources: ['*']),
            new Statement(PolicyEffect::ALLOW, ['posts:view'], null, $broken),
        ])]), 'posts:*');

        self::assertSame(['broken#1'], \array_map(static fn (Refusal $refusal): ?string => $refusal->statement, $screen->refusals()));
        self::assertSame(RefusalReason::INVALID_STATEMENT, $screen->refusals()[0]->reason);
    }

    /**
     * Without a context factory a check reads only what the caller passes and
     * the subject's built-ins, so only a read of the resource is refused,
     * whether in a condition's key, a string operand or a pattern.
     *
     * @return void
     */
    public function testWithoutAFactoryOnlyTheResourceIsRefused(): void
    {
        [$screen, $subject] = $this->screen();

        $screen->screen($this->sources($subject, [new Policy('reads', [
            new Statement(PolicyEffect::DENY, ['posts:view'], null, ['eq' => ['plan.tier' => 'pro', 'subject.id' => '${request.ip}']]),
            new Statement(PolicyEffect::DENY, ['posts:view'], null, ['eq' => ['input.owner' => '${resource.owner}']]),
            new Statement(PolicyEffect::DENY, ['posts:view'], ['posts:${resource.id}']),
        ])]), 'posts:*');

        self::assertSame(['resource.owner', 'resource.id'], \array_map(static fn (Refusal $refusal): ?string => $refusal->key, $screen->refusals()));
        $reasons = \array_map(static fn (Refusal $refusal): RefusalReason => $refusal->reason, $screen->refusals());

        self::assertSame([RefusalReason::RESOURCE_NAMESPACE, RefusalReason::RESOURCE_NAMESPACE], $reasons);
    }

    /**
     * Return a screen of `posts:view` on posts, for a stored subject.
     *
     * @return array{\SineMacula\Laravel\Authorization\Query\StatementScreen, \SineMacula\Laravel\Authorization\Subject}
     */
    private function screen(): array
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $subject = new Subject($user, $user);

        return [new StatementScreen('posts:view', self::TYPE, $subject), $subject];
    }

    /**
     * Return the sources of a check about the subject, with the policies,
     * guardrails and boundaries given, and the caller's input.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy>|null  $guardrails
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy>  $boundaries
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckSources
     */
    private function sources(Subject $subject, array $policies, ?array $guardrails = [], array $boundaries = []): CheckSources
    {
        $context = new CheckContext(['input' => ['type' => self::TYPE, 'nul' => "a\0b"]], [], null, new PrincipalSelectors($subject));

        return new CheckSources($policies, $guardrails, $boundaries, $context, static fn (): ?string => null, new SessionCaps);
    }

    /**
     * Return the subject's reference, as a selector names it.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return string
     */
    private function reference(Subject $subject): string
    {
        /** @var \Tests\Feature\Stubs\StubIdentity $user */
        $user = $subject->subject;

        return $user->getMorphClass() . ':u1';
    }
}
