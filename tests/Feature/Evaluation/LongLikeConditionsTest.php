<?php

declare(strict_types = 1);

namespace Tests\Feature\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use Tests\Feature\Stubs\StubGrantee;
use Tests\TestCase;

/**
 * Feature tests for `like` on a value or operand too long for `fnmatch()`,
 * decided by `check()` with Laravel's error handler and with warnings silenced.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConditionEvaluator::class)]
final class LongLikeConditionsTest extends TestCase
{
    /** @var string The action the policies decide. */
    private const string ACTION = 'posts:read';

    /**
     * A deny whose `like` value is too long applies over a held permission.
     *
     * @return void
     */
    public function testADenyOnALongValueApplies(): void
    {
        $agent = ['agent' => \str_repeat('a bot ', \PHP_MAXPATHLEN)];

        self::assertSame(DecisionReason::EXPLICIT_DENY, self::decide('deny', '*bot*', $agent)->reason);
        self::assertSame(DecisionReason::EXPLICIT_DENY, self::silenced(static fn (): Decision => self::decide('deny', '*bot*', $agent))->reason);
    }

    /**
     * A deny whose substituted `like` operand is too long once escaped applies
     * over a held permission.
     *
     * @return void
     */
    public function testADenyOnALongSubstitutedOperandApplies(): void
    {
        $input = ['agent' => 'a bot', 'pattern' => \str_repeat('*', \intdiv(\PHP_MAXPATHLEN, 2))];

        self::assertSame(DecisionReason::EXPLICIT_DENY, self::decide('deny', '${input.pattern}', $input)->reason);
        self::assertSame(DecisionReason::EXPLICIT_DENY, self::silenced(static fn (): Decision => self::decide('deny', '${input.pattern}', $input))->reason);
    }

    /**
     * An allow whose `like` value is too long is undecidable, so it allows
     * nothing.
     *
     * @return void
     */
    public function testAnAllowOnALongValueIsUndecidable(): void
    {
        $agent = ['agent' => \str_repeat('a bot ', \PHP_MAXPATHLEN)];

        foreach ([self::decide('allow', '*bot*', $agent, false), self::silenced(static fn (): Decision => self::decide('allow', '*bot*', $agent, false))] as $decision) {
            self::assertFalse($decision->isAllowed());
            self::assertContains(TraceOutcome::UNDECIDABLE, \array_map(static fn ($entry): TraceOutcome => $entry->outcome, $decision->trace));
        }
    }

    /**
     * Return the decision on the action for a subject, holding it or not, under
     * a policy of one statement testing `input.agent` with `like`.
     *
     * @param  string  $effect
     * @param  string  $operand
     * @param  array<string, string>  $input
     * @param  bool  $isHeld
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private static function decide(string $effect, string $operand, array $input, bool $isHeld = true): Decision
    {
        $user = StubGrantee::query()->firstOrCreate(['id' => 'reader']);

        if ($isHeld && !$user->hasPermission(self::ACTION)) {
            Permission::query()->firstOrCreate(['name' => self::ACTION, 'guard' => 'web']);
            $user->givePermission(self::ACTION);
        }

        $policy = EvaluationPolicy::fromArray(['name' => 'agents', 'statements' => [
            ['effect' => $effect, 'actions' => [self::ACTION], 'conditions' => ['like' => ['input.agent' => $operand]]],
        ]]);

        return Authorization::for($user)->withPolicies([$policy])->check(self::ACTION, null, $input);
    }

    /**
     * Return the decision the callback makes with warnings silenced, as they
     * are outside Laravel's error handler.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authorization\Evaluation\Decision  $callback
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private static function silenced(\Closure $callback): Decision
    {
        \set_error_handler(static fn (): bool => true);

        try {
            return $callback();
        } finally {
            \restore_error_handler();
        }
    }
}
