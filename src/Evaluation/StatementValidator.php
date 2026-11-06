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
 * The `authentication_requirement` operator (N33) tests the reserved key
 * `authentication` alone, has no `_if_exists` form, and takes a requirement as
 * its operand (see `AuthenticationRequirement`), which its key test carries
 * built.
 *
 * @phpstan-type ConditionTest array{key: string, path: list<string>, operator: string, isOptional: bool, operand: mixed, error: string|null}
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

    /** @var string The name of the `_if_exists` form an authentication requirement does not have. */
    private const string REQUIREMENT_IF_EXISTS = AuthenticationRequirement::OPERATOR . ConditionEvaluator::IF_EXISTS;

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
            foreach ($patterns as $pattern) {
                self::assertValidResource($pattern);
            }
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
            $operator = \is_string($name) ? self::operatorOf($name) : null;

            $error = match (true) {
                !\is_string($name)                        => 'conditions must map operator names to key tests',
                $name     === self::REQUIREMENT_IF_EXISTS => "condition operator '{$name}' is not an operator; an authentication requirement has no _if_exists form",
                $operator === null                        => "conditions have an unknown operator '{$name}'",
                !self::isKeyedMap($tests)                 => "condition operator '{$name}' must map context keys to operands",
                default                                   => null,
            };

            if ($error === null) {
                continue;
            }

            $errors[] = $error;
        }

        return $errors;
    }

    /**
     * Return every key test of the well-formed operator entries, in order: its
     * context key, the key's dot path split into segments, the operator it
     * tests with, whether the `_if_exists` suffix lets a missing key pass, the
     * operand, and why it cannot be evaluated, or null when it can. A
     * well-formed authentication requirement's operand is the requirement,
     * built.
     *
     * @param  array<array-key, mixed>  $conditions
     * @return list<ConditionTest>
     */
    public static function conditionTests(array $conditions): array
    {
        $tests = [];

        foreach ($conditions as $name => $keyTests) {
            $operator = self::operatorOf((string) $name);

            if (!\is_string($name) || $operator === null || !self::isKeyedMap($keyTests)) {
                continue;
            }

            foreach ($keyTests as $key => $operand) {
                $error = self::testError($key, $operator, $operand);

                $tests[] = [
                    'key'        => $key,
                    'path'       => \explode('.', $key),
                    'operator'   => $operator,
                    'isOptional' => $operator !== $name,
                    'operand'    => $operator === AuthenticationRequirement::OPERATOR && $error === null ? AuthenticationRequirement::fromOperand($operand) : $operand,
                    'error'      => $error,
                ];
            }
        }

        return $tests;
    }

    /**
     * Return the operator an operator name tests with: the authentication
     * requirement operator itself, or what `ConditionEvaluator::operatorOf()`
     * gives for any other name.
     *
     * @param  string  $name
     * @return string|null
     */
    private static function operatorOf(string $name): ?string
    {
        return $name === AuthenticationRequirement::OPERATOR ? $name : ConditionEvaluator::operatorOf($name);
    }

    /**
     * Describe why one key test cannot be evaluated: an operand of the wrong
     * type, a malformed `${…}` reference in a string operand, or a malformed
     * authentication requirement.
     *
     * @param  string  $key
     * @param  string  $operator
     * @param  mixed  $operand
     * @return string|null
     */
    private static function testError(string $key, string $operator, mixed $operand): ?string
    {
        if ($operator === AuthenticationRequirement::OPERATOR) {
            return self::requirementError($key, $operand);
        }

        $error = ConditionEvaluator::operandError($operator, $operand);

        if ($error !== null) {
            return "condition '{$key}' has an {$error}";
        }

        return \is_string($operand) && ContextInterpolator::hasMalformedReference($operand)
            ? "condition '{$key}' has a malformed \${…} reference"
            : null;
    }

    /**
     * Describe why an authentication requirement test cannot be evaluated: it
     * tests a key other than `authentication`, or its operand states no
     * requirement.
     *
     * @param  string  $key
     * @param  mixed  $operand
     * @return string|null
     */
    private static function requirementError(string $key, mixed $operand): ?string
    {
        if ($key !== AuthenticationRequirement::KEY) {
            return 'condition operator \'' . AuthenticationRequirement::OPERATOR . '\' tests the key \'' . AuthenticationRequirement::KEY . "' alone, not '{$key}'";
        }

        $error = AuthenticationRequirement::errorOf($operand);

        return $error === null ? null : "authentication {$error}";
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
        if (!\is_array($tests) || $tests === []) {
            return false;
        }

        foreach (\array_keys($tests) as $key) {
            if (!\is_string($key)) {
                return false;
            }
        }

        return true;
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
        if (!\is_array($patterns) || $patterns === [] || !\array_is_list($patterns)) {
            return false;
        }

        foreach ($patterns as $pattern) {
            if (!\is_string($pattern) || $pattern === '') {
                return false;
            }
        }

        return true;
    }
}
