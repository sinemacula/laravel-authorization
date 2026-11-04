<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;

/**
 * Immutable policy statement.
 *
 * A statement binds an effect (allow or deny) to one or more action and
 * resource patterns and an optional condition map. The evaluator walks every
 * statement in order, asking each one whether it applies to the inbound
 * `(action, resource, context)` tuple.
 *
 * Conditions are expressed as a map of context keys to an operator map, for
 * example `['tenant' => ['eq' => 'org-1']]`, or to a plain value compared by
 * strict equality. A test that cannot be decided (a missing context key, a
 * `${…}` reference that cannot be resolved, a context value of the wrong type)
 * is undecidable rather than false, and a malformed test is invalid; see
 * `assess()`. The evaluator applies a deny whose test is undecidable and denies
 * the whole check on an invalid one, so neither ever skips a deny.
 *
 * Documents are validated on hydration: unknown keys, an empty resource list,
 * an empty operator map, an unknown operator or a malformed operand are
 * refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Statement
{
    /** @var string Trace detail for a statement whose action or resource patterns do not cover the check. */
    private const string TARGET_MISMATCH = 'action/resource did not match';

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
        StatementValidator::assertKnownKeys($data);

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
     * Determine whether the statement's action and resource patterns
     * definitively cover the supplied action and optional resource.
     *
     * A check without a resource is covered only by a statement whose resources
     * include `*`; a statement scoped to particular resources never covers it.
     * A resource pattern whose `${…}` reference cannot be resolved does not
     * cover the resource here: use `assess()` for the undecidable outcome.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null  $interpolator
     * @param  object|null  $principal
     * @param  array<string, mixed>  $context
     * @return bool
     */
    public function matches(string $action, ?string $resource = null, ?ContextInterpolator $interpolator = null, ?object $principal = null, array $context = []): bool
    {
        return $this->matchesTarget($action, new InterpolationScope($interpolator, $principal, $resource, $context))->holds();
    }

    /**
     * Determine whether every condition definitively holds for the supplied
     * context. A condition that cannot be decided does not hold here: use
     * `assess()` for the undecidable outcome.
     *
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null  $interpolator
     * @param  object|null  $principal
     * @param  string|null  $resource
     * @return bool
     */
    public function conditionsSatisfiedBy(array $context, ?ContextInterpolator $interpolator = null, ?object $principal = null, ?string $resource = null): bool
    {
        return $this->assessConditions(new InterpolationScope($interpolator, $principal, $resource, $context))->holds();
    }

    /**
     * Assess the statement against a check: whether its patterns and conditions
     * match, definitively do not, cannot be decided, or are malformed.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null  $interpolator
     * @param  object|null  $principal
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    public function assess(string $action, ?string $resource = null, array $context = [], ?ContextInterpolator $interpolator = null, ?object $principal = null): MatchResult
    {
        $scope  = new InterpolationScope($interpolator, $principal, $resource, $context);
        $target = $this->matchesTarget($action, $scope);

        if ($target->outcome === MatchOutcome::DOES_NOT_MATCH) {
            return $target;
        }

        return $target->and($this->assessConditions($scope));
    }

    /**
     * Assess the action and resource patterns against the check.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private function matchesTarget(string $action, InterpolationScope $scope): MatchResult
    {
        return match (true) {
            !$this->matchesAction($action)         => MatchResult::doesNotMatch(self::TARGET_MISMATCH),
            $scope->resource !== null              => $this->matchesResource($scope->resource, $scope),
            \in_array('*', $this->resources, true) => MatchResult::matches(),
            default                                => MatchResult::doesNotMatch(self::TARGET_MISMATCH),
        };
    }

    /**
     * Assess every condition against the context.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private function assessConditions(InterpolationScope $scope): MatchResult
    {
        $result = MatchResult::matches();

        foreach ($this->conditions as $key => $expected) {
            $result = $result->and($this->assessCondition($key, $expected, $scope));
        }

        return $result;
    }

    /**
     * Assess a single condition key/value pair.
     *
     * @param  int|string  $key
     * @param  mixed  $expected
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private function assessCondition(int|string $key, mixed $expected, InterpolationScope $scope): MatchResult
    {
        if (!\is_string($key)) {
            return MatchResult::invalid('a condition key is not a string');
        }

        // A malformed condition is invalid whatever the context holds, so its
        // shape is checked before the key is looked up.
        $error   = StatementValidator::conditionError($key, $expected);
        $problem = match (true) {
            $error !== null                           => MatchResult::invalid($error),
            !\array_key_exists($key, $scope->context) => MatchResult::undecidable("key '{$key}' is missing from the context"),
            default                                   => null,
        };

        return $problem ?? (\is_array($expected)
            ? $this->assessOperators($key, $expected, $scope)
            : $this->assessEquality($key, $expected, $scope));
    }

    /**
     * Assess a condition written as a plain value: strict equality with the
     * context value.
     *
     * @param  string  $key
     * @param  mixed  $expected
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private function assessEquality(string $key, mixed $expected, InterpolationScope $scope): MatchResult
    {
        $resolved = \is_string($expected) ? $scope->literal($expected) : $expected;

        if (\is_string($expected) && $resolved === null) {
            return MatchResult::undecidable("condition '{$key}' references a value that cannot be resolved");
        }

        return MatchResult::fromBool($resolved === $scope->context[$key]);
    }

    /**
     * Assess every operator of a condition.
     *
     * @param  string  $key
     * @param  array<array-key, mixed>  $operators
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private function assessOperators(string $key, array $operators, InterpolationScope $scope): MatchResult
    {
        $result = MatchResult::matches();

        foreach ($operators as $operator => $operand) {
            $result = $result->and($this->assessOperator($key, (string) $operator, $operand, $scope));
        }

        return $result;
    }

    /**
     * Assess one operator of a condition whose shape has been validated.
     *
     * A literal operand of the wrong type was refused with the condition, so an
     * operand the evaluator still finds malformed came from a substituted
     * value: like any context value of the wrong type, it is undecidable.
     *
     * @param  string  $key
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private function assessOperator(string $key, string $operator, mixed $operand, InterpolationScope $scope): MatchResult
    {
        $resolved = \is_string($operand) ? self::resolveOperand($operator, $operand, $scope) : $operand;

        if (\is_string($operand) && $resolved === null) {
            return MatchResult::undecidable("condition '{$key}' references a value that cannot be resolved");
        }

        $result  = ConditionEvaluator::evaluate($operator, $resolved, $scope->context[$key]);
        $outcome = $result->outcome === MatchOutcome::INVALID ? MatchOutcome::UNDECIDABLE : $result->outcome;
        $detail  = $result->outcome === MatchOutcome::INVALID ? "the substituted operand is an {$result->detail}" : $result->detail;

        return $detail === '' ? $result : new MatchResult($outcome, "condition '{$key}': {$detail}");
    }

    /**
     * Interpolate a string operand, preparing a pattern operand for
     * `fnmatch()`. Returns null when a reference cannot be resolved.
     *
     * @param  string  $operator
     * @param  string  $operand
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return string|null
     */
    private static function resolveOperand(string $operator, string $operand, InterpolationScope $scope): ?string
    {
        return \in_array($operator, ConditionEvaluator::PATTERN_OPERATORS, true)
            ? $scope->pattern($operand)
            : $scope->literal($operand);
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

        if ($resources === []) {
            throw new \InvalidArgumentException('Policy statement resources must not be empty; omit the key to cover every resource.');
        }

        \array_walk($resources, static fn (string $pattern) => StatementValidator::assertValidResource($pattern));

        return $resources;
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

            StatementValidator::assertValidCondition($key, $value);

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
     * Action patterns use `fnmatch` with `FNM_NOESCAPE` so backslashes are
     * compared literally. Resource patterns get the same literal backslashes by
     * escaping instead, since their substituted values must be escaped too (see
     * `matchesResource()`).
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
     * Assess the resource against the configured patterns.
     *
     * Each pattern is interpolated with its substituted values escaped, so a
     * value only ever matches itself. A pattern whose reference cannot be
     * resolved makes the result undecidable unless another pattern matches.
     *
     * @param  string  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private function matchesResource(string $resource, InterpolationScope $scope): MatchResult
    {
        $unresolved = false;

        foreach ($this->resources as $pattern) {
            $resolved   = $scope->pattern($pattern);
            $unresolved = $unresolved || $resolved === null;

            if ($resolved !== null && \fnmatch($resolved, $resource)) {
                return MatchResult::matches();
            }
        }

        return $unresolved
            ? MatchResult::undecidable('a resource pattern references a value that cannot be resolved')
            : MatchResult::doesNotMatch(self::TARGET_MISMATCH);
    }
}
