<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * Internal helper refusing malformed statements before they are stored or
 * evaluated.
 *
 * A statement is refused whole when any part is wrong: an unknown key (so a
 * mistyped `conditions` never becomes an unconditional statement), an empty
 * resource list, a condition that is neither a value nor a non-empty operator
 * map, an unknown operator, an operand of the wrong type or a malformed `${…}`
 * reference. It is not part of the public API.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StatementValidator
{
    /** @var list<string> The keys a statement may carry. */
    public const array KEYS = ['effect', 'actions', 'resources', 'conditions'];

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
     * Refuse a condition that cannot be evaluated.
     *
     * @param  string  $key
     * @param  mixed  $condition
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertValidCondition(string $key, mixed $condition): void
    {
        $error = self::conditionError($key, $condition);

        if ($error !== null) {
            throw new \InvalidArgumentException("Policy statement {$error}.");
        }
    }

    /**
     * Refuse a resource pattern with a malformed `${…}` reference.
     *
     * @param  string  $pattern
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertValidResource(string $pattern): void
    {
        if (ContextInterpolator::hasMalformedReference($pattern)) {
            throw new \InvalidArgumentException("Policy statement resource pattern '{$pattern}' has a malformed \${…} reference.");
        }
    }

    /**
     * Describe why a condition cannot be evaluated, or return null when it is
     * well formed: an empty operator map, a non-string operator name, an
     * unknown operator, an operand of the wrong type, or a malformed `${…}`
     * reference in a string value or operand.
     *
     * @param  string  $key
     * @param  mixed  $condition
     * @return string|null
     */
    public static function conditionError(string $key, mixed $condition): ?string
    {
        return \is_array($condition)
            ? self::operatorMapError($key, $condition)
            : self::referenceError($key, $condition);
    }

    /**
     * Describe why an operator map cannot be evaluated, reporting the first
     * fault.
     *
     * @param  string  $key
     * @param  array<array-key, mixed>  $operators
     * @return string|null
     */
    private static function operatorMapError(string $key, array $operators): ?string
    {
        if ($operators === []) {
            return "condition '{$key}' has no operators";
        }

        $error = null;

        foreach ($operators as $operator => $operand) {
            $error ??= self::operatorError($key, $operator, $operand);
        }

        return $error;
    }

    /**
     * Describe why one operator of a condition cannot be evaluated.
     *
     * @param  string  $key
     * @param  int|string  $operator
     * @param  mixed  $operand
     * @return string|null
     */
    private static function operatorError(string $key, int|string $operator, mixed $operand): ?string
    {
        if (!\is_string($operator)) {
            return "condition '{$key}' must map operator names to operands";
        }

        $error = ConditionEvaluator::operandError($operator, $operand);

        return $error !== null ? "condition '{$key}' has an {$error}" : self::referenceError($key, $operand);
    }

    /**
     * Describe a malformed `${…}` reference in a string value or operand.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return string|null
     */
    private static function referenceError(string $key, mixed $value): ?string
    {
        return \is_string($value) && ContextInterpolator::hasMalformedReference($value)
            ? "condition '{$key}' has a malformed \${…} reference"
            : null;
    }
}
