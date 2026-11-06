<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;

/**
 * Internal helper reading the parts of a statement document and refusing
 * malformed statements before they are stored or evaluated.
 *
 * A statement is refused whole when any part is wrong: an unknown key (so a
 * mistyped `conditions` never becomes an unconditional statement), a malformed
 * `sid`, both or neither of `actions` and `not_actions`, both `resources` and
 * `not_resources`, a pattern list that is not a non-empty list of non-empty
 * strings, conditions that do not map operators to key tests, an unknown
 * operator, an operand of the wrong type or a malformed `${…}` reference. It is
 * not part of the public API.
 *
 * @phpstan-type ConditionTest array{key: string, operator: string, isOptional: bool, operand: mixed, error: string|null}
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StatementValidator
{
    /** @var list<string> The keys a statement may carry. */
    public const array KEYS = ['sid', 'effect', 'actions', 'not_actions', 'resources', 'not_resources', 'conditions'];

    /** @var string What a statement id may be: 1 to 64 letters, digits, `_`, `-`, `:` and `.`. */
    public const string SID_PATTERN = '/\A[A-Za-z0-9_:.\-]{1,64}\z/';

    /**
     * Refuse keys a statement does not define.
     *
     * @param  array<array-key, mixed>  $data
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertKnownKeys(array $data): void
    {
        $unknown = \array_diff(\array_keys($data), self::KEYS);

        if ($unknown !== []) {
            throw new \InvalidArgumentException('Policy statement has unknown keys: ' . \implode(', ', $unknown) . '.');
        }
    }

    /**
     * Refuse a statement that names both or neither of `actions` and
     * `not_actions`, or both `resources` and `not_resources`, or that gives any
     * of them as other than a non-empty list of non-empty strings.
     *
     * A statement built in code is held to the same rule as one read from a
     * document, so a computed list that turns out empty never makes
     * `not_actions` or `not_resources` name everything.
     *
     * @param  array<int, string>|null  $actions
     * @param  array<int, string>|null  $notActions
     * @param  array<int, string>|null  $resources
     * @param  array<int, string>|null  $notResources
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertTargets(?array $actions, ?array $notActions, ?array $resources, ?array $notResources): void
    {
        if ($actions === null && $notActions === null) {
            throw new \InvalidArgumentException('Policy statement requires actions or not_actions.');
        }

        if ($actions !== null && $notActions !== null) {
            throw new \InvalidArgumentException('Policy statement takes actions or not_actions, not both.');
        }

        if ($resources !== null && $notResources !== null) {
            throw new \InvalidArgumentException('Policy statement takes resources or not_resources, not both.');
        }

        foreach (['actions' => $actions, 'not_actions' => $notActions, 'resources' => $resources, 'not_resources' => $notResources] as $field => $patterns) {
            if ($patterns !== null && !self::isPatternList($patterns)) {
                throw new \InvalidArgumentException("Policy statement {$field} must be a non-empty list of non-empty strings.");
            }
        }
    }

    /**
     * Refuse a resource pattern that holds a NUL byte, which no resource can
     * match, or a malformed `${…}` reference.
     *
     * @param  string  $pattern
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertValidResource(string $pattern): void
    {
        if (\str_contains($pattern, "\0")) {
            throw new \InvalidArgumentException('Policy statement resource pattern holds a NUL byte.');
        }

        if (ContextInterpolator::hasMalformedReference($pattern)) {
            throw new \InvalidArgumentException("Policy statement resource pattern '{$pattern}' has a malformed \${…} reference.");
        }
    }

    /**
     * Extract the effect from a statement document.
     *
     * @param  array<array-key, mixed>  $data
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect
     *
     * @throws \InvalidArgumentException
     */
    public static function effectOf(array $data): PolicyEffect
    {
        if (!isset($data['effect']) || !\is_string($data['effect'])) {
            throw new \InvalidArgumentException('Policy statement requires a string effect.');
        }

        return PolicyEffect::tryFrom($data['effect'])
            ?? throw new \InvalidArgumentException("Invalid policy effect: '{$data['effect']}'");
    }

    /**
     * Extract the statement id from a statement document, or null when it has
     * none.
     *
     * @param  array<array-key, mixed>  $data
     * @return string|null
     *
     * @throws \InvalidArgumentException
     */
    public static function sidOf(array $data): ?string
    {
        if (!\array_key_exists('sid', $data)) {
            return null;
        }

        $sid = $data['sid'];

        if (!\is_string($sid) || \preg_match(self::SID_PATTERN, $sid) !== 1) {
            throw new \InvalidArgumentException('Policy statement sid must be 1 to 64 letters, digits, \'_\', \'-\', \':\' or \'.\'.');
        }

        return $sid;
    }

    /**
     * Extract a pattern list (`actions`, `not_actions`, `resources` or
     * `not_resources`) from a statement document, or null when it is absent.
     * Resource patterns are also checked for malformed `${…}` references.
     *
     * @param  array<array-key, mixed>  $data
     * @param  string  $field
     * @return list<string>|null
     *
     * @throws \InvalidArgumentException
     */
    public static function patternsOf(array $data, string $field): ?array
    {
        if (!\array_key_exists($field, $data)) {
            return null;
        }

        $patterns = $data[$field];

        if (!self::isPatternList($patterns)) {
            throw new \InvalidArgumentException("Policy statement {$field} must be a non-empty list of non-empty strings.");
        }

        if (\str_ends_with($field, 'resources')) {
            \array_walk($patterns, static fn (string $pattern) => self::assertValidResource($pattern));
        }

        return $patterns;
    }

    /**
     * Extract the conditions map from a statement document.
     *
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    public static function conditionsOf(array $data): array
    {
        $conditions = \array_key_exists('conditions', $data) ? $data['conditions'] : [];

        if (!\is_array($conditions)) {
            throw new \InvalidArgumentException('Policy statement conditions must map operators to key tests.');
        }

        return $conditions;
    }

    /**
     * Work out why the conditions cannot be evaluated as a whole: each entry
     * whose name is not a known operator, or which does not map context keys to
     * operands. Faults in one key's test are left to `conditionTests()`.
     *
     * @param  array<array-key, mixed>  $conditions
     * @return list<string>
     */
    public static function operatorErrors(array $conditions): array
    {
        $errors = [];

        foreach ($conditions as $name => $tests) {
            $operator = \is_string($name) ? ConditionEvaluator::operatorOf($name) : null;

            $errors[] = match (true) {
                !\is_string($name)        => 'conditions must map operator names to key tests',
                $operator === null        => "conditions have an unknown operator '{$name}'",
                !self::isKeyedMap($tests) => "condition operator '{$name}' must map context keys to operands",
                default                   => null,
            };
        }

        return \array_values(\array_filter($errors, static fn (?string $error): bool => $error !== null));
    }

    /**
     * Return every key test of the well-formed operator entries, in order: its
     * context key, the operator it tests with, whether the `_if_exists` suffix
     * lets a missing key pass, the operand, and why it cannot be evaluated, or
     * null when it can.
     *
     * @param  array<array-key, mixed>  $conditions
     * @return list<ConditionTest>
     */
    public static function conditionTests(array $conditions): array
    {
        $tests = [];

        foreach ($conditions as $name => $keyTests) {
            $operator = ConditionEvaluator::operatorOf((string) $name);

            if (!\is_string($name) || $operator === null || !self::isKeyedMap($keyTests)) {
                continue;
            }

            foreach ($keyTests as $key => $operand) {
                $tests[] = [
                    'key'        => $key,
                    'operator'   => $operator,
                    'isOptional' => $operator !== $name,
                    'operand'    => $operand,
                    'error'      => self::testError($key, $operator, $operand),
                ];
            }
        }

        return $tests;
    }

    /**
     * Describe why one key test cannot be evaluated: an operand of the wrong
     * type, or a malformed `${…}` reference in a string operand.
     *
     * @param  string  $key
     * @param  string  $operator
     * @param  mixed  $operand
     * @return string|null
     */
    private static function testError(string $key, string $operator, mixed $operand): ?string
    {
        $error = ConditionEvaluator::operandError($operator, $operand);

        if ($error !== null) {
            return "condition '{$key}' has an {$error}";
        }

        return \is_string($operand) && ContextInterpolator::hasMalformedReference($operand)
            ? "condition '{$key}' has a malformed \${…} reference"
            : null;
    }

    /**
     * Determine whether an operator entry maps one or more context keys to
     * operands.
     *
     * @param  mixed  $tests
     * @return bool
     *
     * @phpstan-assert-if-true non-empty-array<string, mixed> $tests
     */
    private static function isKeyedMap(mixed $tests): bool
    {
        return \is_array($tests)
            && $tests !== []
            && \array_filter(\array_keys($tests), static fn (int|string $key): bool => !\is_string($key)) === [];
    }

    /**
     * Determine whether the value is a non-empty list of non-empty strings.
     *
     * @param  mixed  $patterns
     * @return bool
     *
     * @phpstan-assert-if-true non-empty-list<non-empty-string> $patterns
     */
    private static function isPatternList(mixed $patterns): bool
    {
        return \is_array($patterns)
            && $patterns !== []
            && \array_is_list($patterns)
            && \array_filter($patterns, static fn (mixed $pattern): bool => !\is_string($pattern) || $pattern === '') === [];
    }
}
