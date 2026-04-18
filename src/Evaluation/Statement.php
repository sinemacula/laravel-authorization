<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;

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
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect  $effect
     * @param  array<int, string>  $actions
     * @param  array<int, string>  $resources
     * @param  array<string, mixed>  $conditions
     */
    public function __construct(

        /** Effect contributed when this statement matches — allow or deny. */
        public PolicyEffect $effect,

        /** Action patterns this statement matches, evaluated with fnmatch. */
        public array $actions,

        /** Resource patterns this statement applies to; defaults to `['*']`. */
        public array $resources = ['*'],

        /** Condition map keyed by context key; each value is an operator map. */
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
     * When an interpolator is provided, resource patterns are
     * interpolated before fnmatch comparison, allowing `${...}`
     * tokens in persisted policy documents to resolve at evaluation
     * time.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null  $interpolator
     * @param  object|null  $principal
     * @param  array<string, mixed>  $context
     * @return bool
     */
    public function matches(
        string $action,
        ?string $resource = null,
        ?ContextInterpolator $interpolator = null,
        ?object $principal = null,
        array $context = [],
    ): bool {
        if (!$this->matchesAction($action)) {
            return false;
        }

        return $resource === null || $this->matchesResource($resource, $interpolator, $principal, $context);
    }

    /**
     * Evaluate every condition against the supplied context.
     *
     * When an interpolator is provided, string operands within the
     * condition map are interpolated before operator evaluation,
     * allowing `${...}` tokens in persisted policy documents.
     *
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null  $interpolator
     * @param  object|null  $principal
     * @param  string|null  $resource
     * @return bool
     */
    public function evaluateConditions(
        array $context,
        ?ContextInterpolator $interpolator = null,
        ?object $principal = null,
        ?string $resource = null,
    ): bool {
        foreach ($this->conditions as $key => $expected) {
            if (!$this->evaluateConditionEntry($key, $expected, $context, $interpolator, $principal, $resource)) {
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
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null  $interpolator
     * @param  object|null  $principal
     * @param  string|null  $resource
     * @return bool
     */
    private function evaluateConditionEntry(
        int|string $key,
        mixed $expected,
        array $context,
        ?ContextInterpolator $interpolator = null,
        ?object $principal = null,
        ?string $resource = null,
    ): bool {
        if (!\is_string($key) || !\array_key_exists($key, $context)) {
            return false;
        }

        $interpolated = $interpolator !== null
            ? self::interpolateOperands($expected, $interpolator, $principal, $resource, $context)
            : $expected;

        return $this->evaluateCondition($interpolated, $context[$key]);
    }

    /**
     * Extract the effect from the array representation.
     *
     * @param  array<string, mixed>  $data
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect
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
     * Patterns use `fnmatch` with `FNM_NOESCAPE` so backslashes are
     * compared literally — fully-qualified class names appearing in
     * action or resource strings (`App\Models\Post:42`) stay intact
     * instead of being consumed as shell-glob escape sequences.
     *
     * @param  string  $action
     * @return bool
     */
    private function matchesAction(string $action): bool
    {
        foreach ($this->actions as $pattern) {
            if (\fnmatch($pattern, $action, \FNM_NOESCAPE)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether the resource matches any configured pattern.
     *
     * When an interpolator is supplied, each resource pattern is
     * interpolated before the fnmatch comparison.
     *
     * @param  string  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null  $interpolator
     * @param  object|null  $principal
     * @param  array<string, mixed>  $context
     * @return bool
     */
    private function matchesResource(
        string $resource,
        ?ContextInterpolator $interpolator = null,
        ?object $principal = null,
        array $context = [],
    ): bool {
        foreach ($this->resources as $pattern) {
            $resolved = $interpolator !== null
                ? $interpolator->interpolate($pattern, $principal, $resource, $context)
                : $pattern;

            if (\fnmatch($resolved, $resource, \FNM_NOESCAPE)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Recursively interpolate string operands within a condition payload.
     *
     * If the payload is a plain string, it is interpolated directly.
     * If it is an array (operator map), every string value within the
     * array is interpolated. Non-string values pass through unchanged.
     *
     * @param  mixed  $expected
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator  $interpolator
     * @param  object|null  $principal
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return mixed
     */
    private static function interpolateOperands(
        mixed $expected,
        ContextInterpolator $interpolator,
        ?object $principal,
        ?string $resource,
        array $context,
    ): mixed {
        if (\is_string($expected)) {
            return $interpolator->interpolate($expected, $principal, $resource, $context);
        }

        if (\is_array($expected)) {
            $interpolated = [];

            foreach ($expected as $key => $value) {
                $interpolated[$key] = \is_string($value)
                    ? $interpolator->interpolate($value, $principal, $resource, $context)
                    : $value;
            }

            return $interpolated;
        }

        return $expected;
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
            'eq'     => $actual === $operand,
            'neq'    => $actual !== $operand,
            'in'     => \is_array($operand) && \in_array($actual, $operand, true),
            'not_in' => \is_array($operand) && !\in_array($actual, $operand, true),
            'cidr',
            'starts_with',
            'ends_with',
            'string_like' => self::evaluateStringOperator($operator, $operand, $actual),
            'before'      => ConditionEvaluator::compareTimes($actual, $operand, '<'),
            'after'       => ConditionEvaluator::compareTimes($actual, $operand, '>'),
            'between'     => ConditionEvaluator::matchesBetween($actual, $operand),
            'null'        => $actual === null,
            'not_null'    => $actual !== null,
            'gt'          => ConditionEvaluator::compareNumeric($actual, $operand, '>'),
            'gte'         => ConditionEvaluator::compareNumeric($actual, $operand, '>='),
            'lt'          => ConditionEvaluator::compareNumeric($actual, $operand, '<'),
            'lte'         => ConditionEvaluator::compareNumeric($actual, $operand, '<='),
            'bool'        => ConditionEvaluator::matchesBool($actual, $operand),
            default       => ConditionEvaluator::logUnknownOperator($operator),
        };
    }

    /**
     * Evaluate the string-predicate operators (`cidr`, `starts_with`,
     * `ends_with`, `string_like`) — all of which require both sides
     * to be strings before dispatching to their concrete predicate.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return bool
     */
    private static function evaluateStringOperator(string $operator, mixed $operand, mixed $actual): bool
    {
        if (!\is_string($actual) || !\is_string($operand)) {
            return false;
        }

        return match ($operator) {
            'cidr'        => ConditionEvaluator::matchesCidr($actual, $operand),
            'starts_with' => \str_starts_with($actual, $operand),
            'ends_with'   => \str_ends_with($actual, $operand),
            'string_like' => \fnmatch($operand, $actual, \FNM_NOESCAPE),
            default       => false,
        };
    }
}
