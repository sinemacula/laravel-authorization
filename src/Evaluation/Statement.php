<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Enums\PolicyEffect;

/**
 * Immutable policy statement.
 *
 * A statement binds an effect (allow or deny) to one or more action
 * and resource patterns and an optional condition map. The evaluator
 * walks every statement in order, asking each one whether it applies
 * to the inbound `(action, resource, context)` tuple.
 *
 * Conditions are expressed as a map of context keys to an operator
 * map, for example `['tenant' => ['eq' => 'org-1']]`. Missing context
 * keys cause the condition to fail without throwing, and unknown
 * operators short-circuit to false while emitting a debug log line.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Statement
{
    /**
     * Create a new statement instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\PolicyEffect  $effect
     * @param  array<int, string>  $actions
     * @param  array<int, string>  $resources
     * @param  array<string, mixed>  $conditions
     */
    public function __construct(

        /** Effect contributed when this statement matches — allow or deny. */
        public PolicyEffect $effect,

        /** Action patterns this statement matches against, evaluated with fnmatch. */
        public array $actions,

        /** Resource patterns this statement applies to; defaults to `['*']`. */
        public array $resources = ['*'],

        /** Condition map keyed by context key, each mapped to an operator payload. */
        public array $conditions = [],

    ) {}

    /**
     * Hydrate a statement from its array representation.
     *
     * @param  array<string, mixed>  $data
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $data): self
    {
        return new self(
            effect: self::resolveEffect($data),
            actions: self::resolveActions($data),
            resources: self::resolveResources($data),
            conditions: self::resolveConditions($data),
        );
    }

    /**
     * Serialise the statement for persistence.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $payload = [
            'effect'    => $this->effect->value,
            'actions'   => $this->actions,
            'resources' => $this->resources,
        ];

        if ($this->conditions !== []) {
            $payload['conditions'] = $this->conditions;
        }

        return $payload;
    }

    /**
     * Determine whether the statement applies to the supplied action
     * and optional resource.
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

        return $resource === null || $this->matchesResource($resource);
    }

    /**
     * Evaluate every condition against the supplied context.
     *
     * @param  array<string, mixed>  $context
     * @return bool
     */
    public function evaluateConditions(array $context): bool
    {
        foreach ($this->conditions as $key => $expected) {
            if (!$this->evaluateConditionEntry($key, $expected, $context)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Decide whether a single condition key/value pair is satisfied.
     *
     * @param  int|string  $key
     * @param  mixed  $expected
     * @param  array<string, mixed>  $context
     * @return bool
     */
    private function evaluateConditionEntry(int|string $key, mixed $expected, array $context): bool
    {
        if (!\is_string($key) || !\array_key_exists($key, $context)) {
            return false;
        }

        return $this->evaluateCondition($expected, $context[$key]);
    }

    /**
     * Extract the effect from the array representation.
     *
     * @param  array<string, mixed>  $data
     * @return \SineMacula\Laravel\Authorization\Enums\PolicyEffect
     *
     * @throws \InvalidArgumentException
     */
    private static function resolveEffect(array $data): PolicyEffect
    {
        if (!isset($data['effect']) || !\is_string($data['effect'])) {
            throw new \InvalidArgumentException('Policy statement requires a string effect.');
        }

        return PolicyEffect::tryFrom($data['effect'])
            ?? throw new \InvalidArgumentException("Invalid policy effect: '{$data['effect']}'");
    }

    /**
     * Extract the actions list from the array representation.
     *
     * @param  array<string, mixed>  $data
     * @return array<int, string>
     *
     * @throws \InvalidArgumentException
     */
    private static function resolveActions(array $data): array
    {
        if (!isset($data['actions']) || !\is_array($data['actions']) || $data['actions'] === []) {
            throw new \InvalidArgumentException('Policy statement requires at least one action.');
        }

        return self::normaliseStringList($data['actions'], 'actions');
    }

    /**
     * Extract the resources list from the array representation.
     *
     * @param  array<string, mixed>  $data
     * @return array<int, string>
     *
     * @throws \InvalidArgumentException
     */
    private static function resolveResources(array $data): array
    {
        if (!\array_key_exists('resources', $data)) {
            return ['*'];
        }

        if (!\is_array($data['resources'])) {
            throw new \InvalidArgumentException('Policy statement resources must be an array of strings.');
        }

        $resources = self::normaliseStringList($data['resources'], 'resources');

        return $resources === [] ? ['*'] : $resources;
    }

    /**
     * Extract the conditions map from the array representation.
     *
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function resolveConditions(array $data): array
    {
        if (!\array_key_exists('conditions', $data)) {
            return [];
        }

        if (!\is_array($data['conditions'])) {
            throw new \InvalidArgumentException('Policy statement conditions must be an associative array.');
        }

        $conditions = [];

        foreach ($data['conditions'] as $key => $value) {
            if (!\is_string($key)) {
                throw new \InvalidArgumentException('Policy statement conditions must use string keys.');
            }

            $conditions[$key] = $value;
        }

        return $conditions;
    }

    /**
     * Validate that every member of the supplied list is a string.
     *
     * @param  array<int|string, mixed>  $values
     * @param  string  $fieldName
     * @return array<int, string>
     *
     * @throws \InvalidArgumentException
     */
    private static function normaliseStringList(array $values, string $fieldName): array
    {
        return \array_values(\array_map(static function (mixed $value) use ($fieldName): string {
            if (!\is_string($value)) {
                throw new \InvalidArgumentException("Policy statement {$fieldName} must be strings.");
            }

            return $value;
        }, $values));
    }

    /**
     * Determine whether the action matches any configured pattern.
     *
     * @param  string  $action
     * @return bool
     */
    private function matchesAction(string $action): bool
    {
        foreach ($this->actions as $pattern) {
            if (\fnmatch($pattern, $action)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether the resource matches any configured pattern.
     *
     * @param  string  $resource
     * @return bool
     */
    private function matchesResource(string $resource): bool
    {
        foreach ($this->resources as $pattern) {
            if (\fnmatch($pattern, $resource)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Evaluate a single condition entry against the context value.
     *
     * @param  mixed  $expected
     * @param  mixed  $actual
     * @return bool
     */
    private function evaluateCondition(mixed $expected, mixed $actual): bool
    {
        if (!\is_array($expected)) {
            return $expected === $actual;
        }

        foreach ($expected as $operator => $operand) {
            if (!\is_string($operator) || !self::evaluateOperator($operator, $operand, $actual)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Evaluate a single operator against the context value.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return bool
     */
    private static function evaluateOperator(string $operator, mixed $operand, mixed $actual): bool
    {
        return match ($operator) {
            'eq'          => $actual === $operand,
            'neq'         => $actual !== $operand,
            'in'          => \is_array($operand) && \in_array($actual, $operand, true),
            'not_in'      => \is_array($operand) && !\in_array($actual, $operand, true),
            'cidr'        => \is_string($actual) && \is_string($operand) && ConditionEvaluator::matchesCidr($actual, $operand),
            'starts_with' => \is_string($actual) && \is_string($operand) && \str_starts_with($actual, $operand),
            'ends_with'   => \is_string($actual) && \is_string($operand) && \str_ends_with($actual, $operand),
            'before'      => ConditionEvaluator::compareTimes($actual, $operand, '<'),
            'after'       => ConditionEvaluator::compareTimes($actual, $operand, '>'),
            'between'     => ConditionEvaluator::matchesBetween($actual, $operand),
            default       => ConditionEvaluator::logUnknownOperator($operator),
        };
    }
}
