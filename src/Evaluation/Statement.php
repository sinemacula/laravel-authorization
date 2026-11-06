<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;

/**
 * Immutable policy statement.
 *
 * A statement binds an effect (allow or deny) to the actions and resources it
 * names and an optional condition map. The evaluator walks every statement in
 * order, asking each one whether it applies to the inbound `(action, resource,
 * context)` tuple.
 *
 * A statement names its actions with `actions` (the actions matching any
 * pattern) or `not_actions` (every action matching none), and its resources
 * with `resources`, `not_resources` (every resource matching none) or neither
 * (every resource, and a check that names none). An optional `sid` names the
 * statement in traces; it never changes how the statement is evaluated.
 *
 * An allow statement in a policy attached to a resource names the subjects it
 * applies to in `principals` (AUTHZ-7.3): each a subject reference (`<morph
 * type>:<id>`) or a role by its key (`role:<role id>`). The evaluator applies
 * such an allow only to a subject a selector names, applies an allow in a
 * resource policy that names none to nobody, and an allow that names principals
 * in a policy attached any other way to nobody either. A deny statement takes
 * no `principals`.
 *
 * Conditions map each operator to the context keys it tests and their operands,
 * for example `['eq' => ['input.tenant' => 'org-1']]`, and every test of every
 * operator must hold. A key is a dot path of the check's context, its namespace
 * first, read segment by segment (`request.ip` is the `ip` key of the `request`
 * namespace, never a top-level key named `request.ip`). A test that cannot be
 * decided (a missing context key, a `${…}` reference that cannot be resolved, a
 * context value of the wrong type) is undecidable rather than false, and a
 * malformed test is invalid; see `assess()`. The evaluator applies a deny whose
 * test is undecidable and denies the whole check on an invalid one, so neither
 * ever skips a deny. A missing key passes a test whose operator carries the
 * `_if_exists` suffix, and the `null` operator decides it: `true` holds,
 * `false` does not. A key present with a null value is not missing: every
 * operator but `null` tests the null.
 *
 * The `authentication_requirement` operator states an authentication
 * requirement on the reserved key `authentication` (N33): one test, judged by
 * the bound requirement checker for the check's subject and session, never read
 * from the context. It holds when met, does not hold when unmet, and is
 * undecidable when the checker fails. An allow statement whose requirement
 * alone does not hold says so in its assessment, with the requirement and its
 * unmet parts, so the evaluator can decide `insufficient_authentication`.
 *
 * A statement reads the check's context through its condition keys and its
 * `${…}` references. A namespace is built the first time a check reads a path
 * in it, through `CheckContext`, and kept for the rest of the check, so a
 * namespace no statement reads is never built.
 *
 * Documents are validated on hydration: unknown keys, a malformed sid, an empty
 * pattern list, conditions that do not map operators to key tests, an unknown
 * operator or a malformed operand are refused. A statement built in code is
 * held to the same rule for its targets, so an empty pattern list is refused on
 * construction too, and a computed `not_actions` that turns out empty never
 * names every action.
 *
 * @phpstan-import-type ConditionTest from \SineMacula\Laravel\Authorization\Evaluation\StatementValidator
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Statement
{
    /** @var string Trace detail for a statement whose action or resource patterns do not cover the check. */
    public const string TARGET_MISMATCH = 'action/resource did not match';

    /** @var list<string> Why the conditions cannot be evaluated as a whole, worked out once on construction. */
    private array $operatorErrors;

    /** @var list<ConditionTest> Every key test of the conditions, worked out once on construction. */
    private array $tests;

    /**
     * Create a new statement instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect  $effect
     * @param  array<int, string>|null  $actions
     * @param  array<int, string>|null  $resources
     * @param  array<array-key, mixed>  $conditions
     * @param  string|null  $sid
     * @param  array<int, string>|null  $notActions
     * @param  array<int, string>|null  $notResources
     * @param  array<int, string>|null  $principals
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Effect contributed when this statement matches — allow or deny. */
        public PolicyEffect $effect,

        /** Action patterns this statement names, evaluated with fnmatch; null when it uses `notActions`. */
        public ?array $actions = null,

        /** Resource patterns this statement names; null for every resource, or when it uses `notResources`. */
        public ?array $resources = null,

        /** Condition map keyed by operator; each value maps context keys to operands. */
        public array $conditions = [],

        /** The statement's id within its policy, for traces; null when it has none. */
        public ?string $sid = null,

        /** Action patterns naming every action this statement does not; null when it uses `actions`. */
        public ?array $notActions = null,

        /** Resource patterns naming every resource this statement does not; null when it does not use them. */
        public ?array $notResources = null,

        /** The subjects an allow in a resource policy applies to, each `<type>:<id>` or `role:<role id>`; null when it names none. */
        public ?array $principals = null,
    ) {
        StatementValidator::assertTargets($actions, $notActions, $resources, $notResources);
        StatementValidator::assertPrincipals($effect, $principals);

        $this->operatorErrors = StatementValidator::operatorErrors($conditions);
        $this->tests          = StatementValidator::conditionTests($conditions);
    }

    /**
     * Hydrate a statement from its array representation.
     *
     * @param  array<array-key, mixed>  $data
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $data): self
    {
        StatementValidator::assertKnownKeys($data);

        $statement = new self(
            effect: StatementValidator::effectOf($data),
            actions: StatementValidator::patternsOf($data, 'actions'),
            resources: StatementValidator::patternsOf($data, 'resources'),
            conditions: StatementValidator::conditionsOf($data),
            sid: StatementValidator::sidOf($data),
            notActions: StatementValidator::patternsOf($data, 'not_actions'),
            notResources: StatementValidator::patternsOf($data, 'not_resources'),
            principals: StatementValidator::principalsOf($data),
        );

        foreach ([...$statement->operatorErrors, ...\array_column($statement->tests, 'error')] as $error) {
            if ($error !== null) {
                throw new \InvalidArgumentException("Policy statement {$error}.");
            }
        }

        return $statement;
    }

    /**
     * Serialise the statement for persistence, with exactly the keys it was
     * given: a statement without `resources` or `not_resources` stays without
     * them.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return \array_filter([
            'sid'           => $this->sid,
            'effect'        => $this->effect->value,
            'actions'       => $this->actions,
            'not_actions'   => $this->notActions,
            'resources'     => $this->resources,
            'not_resources' => $this->notResources,
            'principals'    => $this->principals,
            'conditions'    => $this->conditions === [] ? null : $this->conditions,
        ], static fn (mixed $value): bool => $value !== null);
    }

    /**
     * Determine whether the statement's action and resource patterns
     * definitively cover the supplied action and optional resource.
     *
     * A check without a resource is covered only by a statement without
     * `resources` or `not_resources`, or whose `resources` include `*`; a
     * statement scoped to particular resources, or to every resource but some,
     * never covers it. A resource pattern whose `${…}` reference cannot be
     * resolved does not cover the resource here: use `assess()` for the
     * undecidable outcome.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null  $interpolator
     * @param  array<array-key, mixed>|\SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @return bool
     */
    public function matches(string $action, ?string $resource = null, ?ContextInterpolator $interpolator = null, array|CheckContext $context = []): bool
    {
        return $this->coversAction($action)
            && $this->matchesTarget(new InterpolationScope($interpolator, $resource, $context))->holds();
    }

    /**
     * Determine whether every condition definitively holds for the supplied
     * context. A condition that cannot be decided does not hold here: use
     * `assess()` for the undecidable outcome.
     *
     * A context given as an array is the check's namespaces, already built.
     *
     * @param  array<array-key, mixed>|\SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null  $interpolator
     * @return bool
     */
    public function conditionsSatisfiedBy(array|CheckContext $context, ?ContextInterpolator $interpolator = null): bool
    {
        return $this->assessConditions(new InterpolationScope($interpolator, null, $context))->holds();
    }

    /**
     * Assess the statement against a check: whether its patterns and conditions
     * match, definitively do not, cannot be decided, or are malformed.
     *
     * A context given as an array is the check's namespaces, already built.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<array-key, mixed>|\SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null  $interpolator
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    public function assess(string $action, ?string $resource = null, array|CheckContext $context = [], ?ContextInterpolator $interpolator = null): MatchResult
    {
        // Most statements of a policy do not name the action, so that case
        // returns before the scope is built.
        if (!$this->coversAction($action)) {
            return MatchResult::doesNotMatch(self::TARGET_MISMATCH);
        }

        $scope  = new InterpolationScope($interpolator, $resource, $context);
        $target = $this->matchesTarget($scope);

        if ($target->outcome === MatchOutcome::DOES_NOT_MATCH) {
            return $target;
        }

        // An unmet authentication requirement is kept only when the resource
        // definitely matched, so an undecidable resource pattern never makes
        // the statement a candidate for insufficient authentication.
        $conditions = $this->assessConditions($scope);
        $result     = $target->and($conditions)->withConditions($conditions->conditions ?? []);

        return $result->unmetRequirement === null || $target->holds() ? $result : $result->withUnmetRequirement(null);
    }

    /**
     * Determine whether the statement names the action: one of its `actions`
     * patterns covers it, or none of its `not_actions` patterns does. The
     * evaluator asks this first, since most statements of a policy do not name
     * the action being checked.
     *
     * Action patterns use `fnmatch` with `FNM_NOESCAPE` so backslashes are
     * compared literally. Resource patterns get the same literal backslashes by
     * escaping instead, since their substituted values must be escaped too (see
     * `matchesResource()`).
     *
     * @param  string  $action
     * @return bool
     */
    public function coversAction(string $action): bool
    {
        foreach (($this->notActions === null ? $this->actions : $this->notActions) ?? [] as $pattern) {
            if (\fnmatch($pattern, $action, \FNM_NOESCAPE)) {
                return $this->notActions === null;
            }
        }

        return $this->notActions !== null;
    }

    /**
     * Assess the resource patterns against a check whose action the statement
     * names. A statement without `resources` or `not_resources` names every
     * resource and a check that names none; otherwise a check without a
     * resource is named only by `resources` that include `*`.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private function matchesTarget(InterpolationScope $scope): MatchResult
    {
        return match (true) {
            $this->resources === null && $this->notResources === null           => MatchResult::matches(),
            $scope->resource !== null                                           => $this->matchesResource($scope->resource, $scope),
            $this->resources !== null && \in_array('*', $this->resources, true) => MatchResult::matches(),
            default                                                             => MatchResult::doesNotMatch(self::TARGET_MISMATCH),
        };
    }

    /**
     * Assess every key test of the conditions against the context, recording
     * each key with whether all of its tests held.
     *
     * The authentication requirement, when the statement states one, is
     * combined last, and its unmet parts are kept only when every other test
     * held, so the result names the requirement exactly when it alone kept the
     * conditions from holding.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private function assessConditions(InterpolationScope $scope): MatchResult
    {
        $result      = $this->operatorErrors === [] ? MatchResult::matches() : MatchResult::invalid($this->operatorErrors[0]);
        $requirement = MatchResult::matches();
        $held        = [];

        foreach ($this->tests as $test) {
            $part = self::assessTest($test, $scope);

            if ($test['operator'] === AuthenticationRequirement::OPERATOR) {
                $requirement = $part;
            } elseif ($part->outcome !== MatchOutcome::MATCHES) {
                $result = $result->and($part);
            }

            $held[$test['key']] = ($held[$test['key']] ?? true) && $part->outcome === MatchOutcome::MATCHES;
        }

        $combined = $result->and($requirement)->withConditions($held);

        return $combined->unmetRequirement === null || $result->holds() ? $combined : $combined->withUnmetRequirement(null);
    }

    /**
     * Assess a single key test.
     *
     * A malformed test is invalid whatever the context holds, so its shape
     * (worked out on construction) is checked before the key is looked up, and
     * its namespace is never built for it. An authentication requirement is
     * judged by the context's requirement check, never read as a key.
     *
     * @param  ConditionTest  $test
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function assessTest(array $test, InterpolationScope $scope): MatchResult
    {
        return match (true) {
            $test['error'] !== null                               => MatchResult::invalid($test['error']),
            $test['operand'] instanceof AuthenticationRequirement => $scope->context->assessRequirement($test['operand']),
            default                                               => self::assessKey($test, $scope),
        };
    }

    /**
     * Assess a well-formed key test against the value of its key.
     *
     * @param  ConditionTest  $test
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function assessKey(array $test, InterpolationScope $scope): MatchResult
    {
        [$isPresent, $actual] = $scope->context->find($test['path']);

        return $isPresent
            ? self::assessOperator($test['key'], $test['operator'], $test['operand'], $actual, $scope)
            : self::assessMissingKey($test);
    }

    /**
     * Assess a test of a key the context lacks: it passes under `_if_exists`,
     * `null` decides it (`true` holds, `false` does not), and any other test
     * cannot be decided.
     *
     * @param  ConditionTest  $test
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function assessMissingKey(array $test): MatchResult
    {
        return match (true) {
            $test['isOptional']          => MatchResult::matches(),
            $test['operator'] === 'null' => MatchResult::fromBool($test['operand'] === true),
            default                      => MatchResult::undecidable("key '{$test['key']}' is missing from the context"),
        };
    }

    /**
     * Assess one key test whose shape has been validated, against the value of
     * a key the context carries.
     *
     * A literal operand of the wrong type was refused with the condition, so an
     * operand the evaluator still finds malformed came from a substituted
     * value: like any context value of the wrong type, it is undecidable.
     *
     * @param  string  $key
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function assessOperator(string $key, string $operator, mixed $operand, mixed $actual, InterpolationScope $scope): MatchResult
    {
        $resolved = \is_string($operand) ? self::resolveOperand($operator, $operand, $scope) : $operand;

        if (\is_string($operand) && $resolved === null) {
            return MatchResult::undecidable("condition '{$key}' references a value that cannot be resolved");
        }

        $result  = ConditionEvaluator::evaluate($operator, $resolved, $actual);
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
     * Assess the resource against the statement's `resources`, or its
     * `not_resources`, which name every resource none of them covers.
     *
     * Each pattern is interpolated with its substituted values escaped, so a
     * value only ever matches itself. A pattern whose reference cannot be
     * resolved makes the result undecidable unless another pattern covers the
     * resource.
     *
     * @param  string  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private function matchesResource(string $resource, InterpolationScope $scope): MatchResult
    {
        $isNegated = $this->notResources !== null;
        $isCovered = self::isCoveredByAny(($isNegated ? $this->notResources : $this->resources) ?? [], $resource, $scope);

        return match (true) {
            $isCovered === null       => MatchResult::undecidable('a resource pattern references a value that cannot be resolved'),
            $isCovered !== $isNegated => MatchResult::matches(),
            default                   => MatchResult::doesNotMatch(self::TARGET_MISMATCH),
        };
    }

    /**
     * Determine whether any of the patterns covers the resource: true when one
     * does, false when none does, and null when none does but one references a
     * value that cannot be resolved or that holds a NUL byte.
     *
     * @param  array<int, string>  $patterns
     * @param  string  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return bool|null
     */
    private static function isCoveredByAny(array $patterns, string $resource, InterpolationScope $scope): ?bool
    {
        $unresolved = false;

        foreach ($patterns as $pattern) {
            // A substituted value holding a NUL byte names nothing, so the
            // pattern is unresolved, as one whose reference cannot be resolved
            // is, and never reaches fnmatch().
            $resolved   = $scope->pattern($pattern);
            $resolved   = $resolved !== null && \str_contains($resolved, "\0") ? null : $resolved;
            $unresolved = $unresolved || $resolved === null;

            if ($resolved !== null && self::covers($resolved, $resource)) {
                return true;
            }
        }

        return $unresolved ? null : false;
    }

    /**
     * Determine whether a resolved pattern covers the resource. A type alone
     * (`post:*`, N6) is covered only by a pattern that covers every record of
     * the type, which also covers the type with an empty id, so a pattern that
     * needs an id character, such as `post:?` or `post:[!0-9]`, does not cover
     * it: its `*` is a literal character, not a wildcard.
     *
     * @param  string  $pattern
     * @param  string  $resource
     * @return bool
     */
    private static function covers(string $pattern, string $resource): bool
    {
        return \fnmatch($pattern, $resource)
            && (!\str_ends_with($resource, ':*') || \fnmatch($pattern, \substr($resource, 0, -1)));
    }
}
