<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\ConditionClassifier;
use SineMacula\Laravel\Authorization\Evaluation\ConditionResult;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\InterpolationScope;
use SineMacula\Laravel\Authorization\Evaluation\MatchResult;
use SineMacula\Laravel\Authorization\Evaluation\RequirementCheck;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Feature\Stubs\StubRequirementChecker;

/**
 * Unit tests for the condition classifier: what each condition test of an
 * explained check found, as a statement assessed through an explaining context
 * records it, its outcome kept exactly as the statement gave it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConditionClassifier::class)]
final class ConditionClassifierTest extends TestCase
{
    /**
     * A test of a present key holds or fails; one of a null it does not accept
     * is `null`, of a value of the wrong type `wrong_type`, and two tests of
     * one key are recorded apart.
     *
     * @return void
     */
    public function testATestOfAPresentKey(): void
    {
        $conditions = ['eq' => ['input.a' => 'x', 'input.b' => 'x', 'input.n' => 'x'], 'gt' => ['input.a' => 1, 'input.w' => 1], 'null' => ['input.n' => true]];
        $tests      = self::tests($conditions, ['a' => 'x', 'b' => 'y', 'n' => null, 'w' => 'many']);

        self::assertEquals([
            new ConditionResult('input.a', 'eq', ConditionOutcome::HELD),
            new ConditionResult('input.b', 'eq', ConditionOutcome::FAILED),
            new ConditionResult('input.n', 'eq', ConditionOutcome::NULL),
            new ConditionResult('input.a', 'gt', ConditionOutcome::WRONG_TYPE),
            new ConditionResult('input.w', 'gt', ConditionOutcome::WRONG_TYPE),
            new ConditionResult('input.n', 'null', ConditionOutcome::HELD),
        ], $tests);
    }

    /**
     * A null the operator cannot compare is `null` too, rather than of the
     * wrong type.
     *
     * @return void
     */
    public function testAnUncomparableNullIsNull(): void
    {
        self::assertEquals([new ConditionResult('input.n', 'gt', ConditionOutcome::NULL)], self::tests(['gt' => ['input.n' => 1]], ['n' => null]));
    }

    /**
     * A missing key is `missing` when the test cannot be decided without it,
     * passes under `_if_exists` and `null: true`, and fails under `null:
     * false`, each saying the key was missing.
     *
     * @return void
     */
    public function testATestOfAMissingKey(): void
    {
        $tests = self::tests(['eq' => ['input.a' => 'x'], 'eq_if_exists' => ['input.b' => 'x'], 'null' => ['input.c' => true, 'input.d' => false]], []);

        self::assertEquals([
            new ConditionResult('input.a', 'eq', ConditionOutcome::MISSING, false, true),
            new ConditionResult('input.b', 'eq', ConditionOutcome::HELD, true, true),
            new ConditionResult('input.c', 'null', ConditionOutcome::HELD, false, true),
            new ConditionResult('input.d', 'null', ConditionOutcome::FAILED, false, true),
        ], $tests);
    }

    /**
     * An operand whose reference cannot be resolved is `unresolved`, naming the
     * key referenced; one whose substituted value has the wrong type is
     * `undecidable`.
     *
     * @return void
     */
    public function testAnOperandThatCannotBeUsed(): void
    {
        $tests = self::tests(['eq' => ['input.a' => '${input.nowhere}'], 'gt' => ['input.n' => '${input.limit}']], ['a' => 'x', 'n' => 5, 'limit' => 'abc']);

        self::assertEquals([
            new ConditionResult('input.a', 'eq', ConditionOutcome::UNRESOLVED, false, false, ['input.nowhere']),
            new ConditionResult('input.n', 'gt', ConditionOutcome::UNDECIDABLE),
        ], $tests);
    }

    /**
     * A malformed test is `invalid`, and its key is never looked up.
     *
     * @return void
     */
    public function testAMalformedTestIsInvalid(): void
    {
        $statement = new Statement(PolicyEffect::ALLOW, ['posts:read'], null, ['in' => ['input.a' => 'not-a-list']]);
        $context   = self::explaining([]);
        $result    = $statement->assess('posts:read', null, $context, new ContextInterpolator);

        self::assertSame(MatchOutcome::INVALID, $result->outcome);
        self::assertEquals([new ConditionResult('input.a', 'in', ConditionOutcome::INVALID)], $context->takeAssessment()[0]);
    }

    /**
     * An authentication requirement is held when met, failed when unmet and
     * undecidable when it cannot be checked.
     *
     * @return void
     */
    public function testAnAuthenticationRequirement(): void
    {
        $conditions = ['authentication_requirement' => ['authentication' => ['multifactor' => []]]];
        $statement  = new Statement(PolicyEffect::ALLOW, ['posts:read'], null, $conditions);
        $outcomes   = [];

        foreach ([RequirementResult::met(), RequirementResult::unmet(['multifactor']), new \RuntimeException('down')] as $answer) {
            $user    = new \stdClass;
            $context = new CheckContext([], [], new RequirementCheck(new StubRequirementChecker($answer), new Subject($user, $user, session: 'session-1')));

            $context->explain();

            $statement->assess('posts:read', null, $context);

            $outcomes[] = $context->takeAssessment()[0][0]->outcome ?? null;
        }

        self::assertSame([ConditionOutcome::HELD, ConditionOutcome::FAILED, ConditionOutcome::UNDECIDABLE], $outcomes);
    }

    /**
     * A failed test decides a deny's conjunction over one that cannot be
     * decided, as it does without explain mode, and both are recorded.
     *
     * @return void
     */
    public function testADefiniteFailureBeatsAnUndecidableTest(): void
    {
        $statement = new Statement(PolicyEffect::DENY, ['posts:read'], null, ['eq' => ['input.absent' => 'x', 'input.a' => 'y']]);
        $context   = self::explaining(['a' => 'x']);
        $plain     = $statement->assess('posts:read', null, ['input' => ['a' => 'x']], new ContextInterpolator);
        $explained = $statement->assess('posts:read', null, $context, new ContextInterpolator);

        self::assertSame(MatchOutcome::DOES_NOT_MATCH, $plain->outcome);
        self::assertSame($plain->outcome, $explained->outcome);
        self::assertSame($plain->conditions, $explained->conditions);

        $outcomes = \array_map(static fn (ConditionResult $test): ConditionOutcome => $test->outcome, $context->takeAssessment()[0] ?? []);

        self::assertSame([ConditionOutcome::MISSING, ConditionOutcome::FAILED], $outcomes);
    }

    /**
     * classify() given a result the evaluator calls invalid for a present key
     * keeps it invalid.
     *
     * @return void
     */
    public function testAnInvalidResultOfAPresentKeyStaysInvalid(): void
    {
        $test   = ['key' => 'input.a', 'path' => ['input', 'a'], 'operator' => 'eq', 'isOptional' => false, 'operand' => 'x', 'error' => null];
        $scope  = new InterpolationScope(null, null, ['input' => ['a' => 'x']]);
        $result = ConditionClassifier::classify($test, MatchResult::invalid('unknown operator'), $scope, []);

        self::assertSame(ConditionOutcome::INVALID, $result->outcome);
    }

    /**
     * Return each test the statement with the conditions recorded, assessed
     * through an explaining context holding the input values.
     *
     * @param  array<string, mixed>  $conditions
     * @param  array<string, mixed>  $input
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\ConditionResult>
     */
    private static function tests(array $conditions, array $input): array
    {
        $statement = new Statement(PolicyEffect::ALLOW, ['posts:read'], null, $conditions);
        $context   = self::explaining($input);

        $statement->assess('posts:read', null, $context, new ContextInterpolator);

        return $context->takeAssessment()[0] ?? [];
    }

    /**
     * Return an explaining context holding the input values.
     *
     * @param  array<string, mixed>  $input
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckContext
     */
    private static function explaining(array $input): CheckContext
    {
        $context = new CheckContext(['input' => $input]);

        $context->explain();

        return $context;
    }
}
