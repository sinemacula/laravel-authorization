<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;

/**
 * Tells, for an explained check, what one condition test found (see
 * `ConditionOutcome`), from the result the statement assessed it to and the
 * key's presence in the context, which the assessment already read, so telling
 * it reads nothing new and builds no namespace.
 *
 * The test keeps the outcome the statement gave it: a missing key passes under
 * `_if_exists` and `null: true`, and `null: false` refuses it; a null value the
 * test does not accept is `null`; an undecidable test on a present key is
 * `unresolved` when a `${…}` reference of its operand could not be resolved,
 * `undecidable` when the substituted operand has the wrong type, or is a string
 * a string operator cannot test (empty, or holding a NUL byte) while the value
 * is one it can, and `wrong_type` otherwise.
 *
 * @phpstan-import-type ConditionTest from \SineMacula\Laravel\Authorization\Evaluation\StatementValidator
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConditionClassifier
{
    /** @var list<string> The operators that test a string value against a string operand, which cannot be empty or hold a NUL byte. */
    private const array STRING_OPERATORS = ['starts_with', 'ends_with', 'like'];

    /**
     * Return what the test found, as an explanation records it, given the
     * result it was assessed to and the references noted as unresolved while it
     * was.
     *
     * @param  ConditionTest  $test
     * @param  \SineMacula\Laravel\Authorization\Evaluation\MatchResult  $part
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @param  list<string>  $unresolved
     * @return \SineMacula\Laravel\Authorization\Evaluation\ConditionResult
     */
    public static function classify(array $test, MatchResult $part, InterpolationScope $scope, array $unresolved): ConditionResult
    {
        $fixed = match (true) {
            $test['error'] !== null                               => ConditionOutcome::INVALID,
            $test['operand'] instanceof AuthenticationRequirement => self::requirementOutcome($part),
            default                                               => null,
        };

        if ($fixed !== null) {
            return new ConditionResult($test['key'], $test['operator'], $fixed, $test['isOptional']);
        }

        // The assessment read this path already, so its namespace is built.
        [$isPresent, $actual] = $scope->context->find($test['path']);

        $outcome = $isPresent ? self::presentOutcome($test, $part, $actual, $unresolved) : self::missingOutcome($part);

        return new ConditionResult($test['key'], $test['operator'], $outcome, $test['isOptional'], !$isPresent, $unresolved);
    }

    /**
     * Return what an authentication requirement's test found: met, unmet, or
     * not checkable.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\MatchResult  $part
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome
     */
    private static function requirementOutcome(MatchResult $part): ConditionOutcome
    {
        return match ($part->outcome) {
            MatchOutcome::MATCHES        => ConditionOutcome::HELD,
            MatchOutcome::DOES_NOT_MATCH => ConditionOutcome::FAILED,
            default                      => ConditionOutcome::UNDECIDABLE,
        };
    }

    /**
     * Return what a test of a key the context lacks found: it passed, under
     * `_if_exists` or `null: true`, it failed, under `null: false`, or it is
     * missing.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\MatchResult  $part
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome
     */
    private static function missingOutcome(MatchResult $part): ConditionOutcome
    {
        return match ($part->outcome) {
            MatchOutcome::MATCHES        => ConditionOutcome::HELD,
            MatchOutcome::DOES_NOT_MATCH => ConditionOutcome::FAILED,
            default                      => ConditionOutcome::MISSING,
        };
    }

    /**
     * Return what a test of a key the context carries found.
     *
     * @param  ConditionTest  $test
     * @param  \SineMacula\Laravel\Authorization\Evaluation\MatchResult  $part
     * @param  mixed  $actual
     * @param  list<string>  $unresolved
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome
     */
    private static function presentOutcome(array $test, MatchResult $part, mixed $actual, array $unresolved): ConditionOutcome
    {
        $isUndecidable = $part->outcome === MatchOutcome::UNDECIDABLE;

        return match (true) {
            $part->outcome === MatchOutcome::MATCHES                              => ConditionOutcome::HELD,
            $part->outcome === MatchOutcome::INVALID                              => ConditionOutcome::INVALID,
            $isUndecidable && $unresolved !== []                                  => ConditionOutcome::UNRESOLVED,
            \str_contains($part->detail, Statement::SUBSTITUTED_OPERAND)          => ConditionOutcome::UNDECIDABLE,
            $isUndecidable && self::isSubstitutedStringUntestable($test, $actual) => ConditionOutcome::UNDECIDABLE,
            $actual        === null                                               => ConditionOutcome::NULL,
            $part->outcome === MatchOutcome::DOES_NOT_MATCH                       => ConditionOutcome::FAILED,
            default                                                               => ConditionOutcome::WRONG_TYPE,
        };
    }

    /**
     * Determine whether an undecidable test is its substituted operand's doing:
     * a string operator against a string value without a NUL byte, which it can
     * test, is left undecidable only by an empty operand or one holding a NUL
     * byte, and a literal operand of either kind is refused with the condition,
     * so the operand came from a substituted value.
     *
     * @param  ConditionTest  $test
     * @param  mixed  $actual
     * @return bool
     */
    private static function isSubstitutedStringUntestable(array $test, mixed $actual): bool
    {
        return \in_array($test['operator'], self::STRING_OPERATORS, true) && \is_string($actual) && !\str_contains($actual, "\0");
    }
}
