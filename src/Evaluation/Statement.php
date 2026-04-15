<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions\Evaluation;

use SineMacula\Laravel\Iam\Permissions\Enums\PolicyEffect;

/**
 * Policy statement.
 *
 * An immutable value object representing a single statement within
 * an IAM-style policy. Each statement declares an effect (allow or
 * deny), the actions and resources it applies to, and optional
 * conditions that must be met.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final readonly class Statement
{
    /**
     * Create a new statement instance.
     *
     * @param  \SineMacula\Laravel\Iam\Permissions\Enums\PolicyEffect  $effect
     * @param  array<int, string>  $actions
     * @param  array<int, string>  $resources
     * @param  array<string, mixed>  $conditions
     */
    public function __construct(
        public PolicyEffect $effect,
        public array $actions,
        public array $resources = ['*'],
        public array $conditions = [],
    ) {}

    /**
     * Create a statement from an associative array.
     *
     * @param  array{effect: string, actions: array<int, string>, resources?: array<int, string>, conditions?: array<string, mixed>}  $data
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $data): self
    {
        $effect = PolicyEffect::tryFrom($data['effect'])
            ?? throw new \InvalidArgumentException("Invalid policy effect: '{$data['effect']}'");

        return new self(
            effect: $effect,
            actions: $data['actions'],
            resources: $data['resources']   ?? ['*'],
            conditions: $data['conditions'] ?? [],
        );
    }

    /**
     * Determine whether the statement matches the given action and
     * optional resource.
     *
     * Uses fnmatch for wildcard pattern matching so that patterns
     * like 'posts:*' will match 'posts:create'.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @return bool
     */
    public function matches(string $action, ?string $resource = null): bool
    {
        if (!$this->matchesAction($action)) {
            return false;
        }

        return !($resource !== null && !$this->matchesResource($resource));
    }

    /**
     * Evaluate the statement conditions against the given context.
     *
     * Returns true when there are no conditions or when all
     * conditions are satisfied by the provided context values.
     *
     * @param  array<string, mixed>  $context
     * @return bool
     */
    public function evaluateConditions(array $context): bool
    {
        foreach ($this->conditions as $key => $expected) {
            if (!array_key_exists($key, $context)) {
                return false;
            }

            if (!$this->evaluateCondition($expected, $context[$key])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine whether the given action matches any of the
     * statement's action patterns.
     *
     * @param  string  $action
     * @return bool
     */
    private function matchesAction(string $action): bool
    {
        foreach ($this->actions as $pattern) {
            if (fnmatch($pattern, $action)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether the given resource matches any of the
     * statement's resource patterns.
     *
     * @param  string  $resource
     * @return bool
     */
    private function matchesResource(string $resource): bool
    {
        foreach ($this->resources as $pattern) {
            if (fnmatch($pattern, $resource)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Evaluate a single condition value against the context value.
     *
     * Supports simple equality checks and associative array
     * conditions for extensible operator-based matching (e.g.
     * CIDR range checks).
     *
     * @param  mixed  $expected
     * @param  mixed  $actual
     * @return bool
     */
    private function evaluateCondition(mixed $expected, mixed $actual): bool
    {
        if (!is_array($expected)) {
            return $expected === $actual;
        }

        foreach ($expected as $operator => $operand) {
            if (!$this->evaluateOperator($operator, $operand, $actual)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Evaluate a condition operator.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return bool
     */
    private function evaluateOperator(string $operator, mixed $operand, mixed $actual): bool
    {
        return match ($operator) {
            'eq'          => $actual === $operand,
            'neq'         => $actual !== $operand,
            'in'          => is_array($operand) && in_array($actual, $operand, true),
            'not_in'      => is_array($operand) && !in_array($actual, $operand, true),
            'cidr'        => is_string($actual) && is_string($operand) && $this->matchesCidr($actual, $operand),
            'starts_with' => is_string($actual) && is_string($operand) && str_starts_with($actual, $operand),
            'ends_with'   => is_string($actual) && is_string($operand) && str_ends_with($actual, $operand),
            default       => false,
        };
    }

    /**
     * Determine whether an IP address falls within a CIDR range.
     *
     * @param  string  $ip
     * @param  string  $cidr
     * @return bool
     */
    private function matchesCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$subnet, $bits] = explode('/', $cidr, 2);

        $ipLong     = ip2long($ip);
        $subnetLong = ip2long($subnet);
        $mask       = -1 << (32 - (int) $bits);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }
}
