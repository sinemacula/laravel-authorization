<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\InterpolationScope;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\StatementValidator;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Compiles the statements one class of rows is decided from, before they are
 * weighed (AUTHZ-10.2, N65): for each statement a check would weigh, the
 * condition a row meets when the statement matches it, which an allow needs,
 * and when it applies to it, which a deny needs.
 *
 * A statement is weighed when it names the action, and, for an allow (a
 * guardrail's or a boundary's included), it applies to the subject, as the
 * policy evaluator tells (`PolicyEvaluator::isForSubject()`); the caller asks
 * only about those. Its outcome on a row is its target's on the row's
 * identifier joined with its conditions', as `Statement::assess()` joins them:
 * the conditions are assessed once, through `Statement::assess()` itself on the
 * statement without its resources, since they never read the row; the target is
 * compiled from its resource patterns, each resolved as `check()` resolves it
 * and compiled to a condition on the row's key (see `ResourcePatterns` and
 * `KeyConditions`). A pattern whose reference cannot be resolved, or resolves
 * to a NUL byte, makes the target undecidable unless another covers the row, as
 * `check()` finds it.
 *
 * A statement is refused, with no pruning, when:
 *
 * - it reads the `resource` namespace, in a condition, an operand or a pattern
 *   (`resource_namespace`);
 * - it reads a namespace whose source is not marked `ScopeInvariant`, or states
 *   an authentication requirement the bound checker, not so marked, would judge
 *   (`scope_variant_source`);
 * - a resource pattern cannot be compared with a key (`resource_pattern`), or
 *   the key cannot be compared with it (`column_type`, `column_collation`);
 * - it cannot be evaluated, and its target names any row (`invalid_statement`).
 *
 * The screen also tells whether a statement has a pattern that resolves, which
 * `fnmatch()` matches against each row's identifier, so the scope can leave out
 * the rows whose identifier it would refuse as too long.
 *
 * Every refusal is kept, once, across every class, so they are thrown together.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StatementScreen
{
    /** @var array<string, \SineMacula\Laravel\Authorization\Query\Refusal> Every refusal found, once each. */
    private array $refusals = [];

    /** @var \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator Resolves the patterns as `check()` does. */
    private readonly ContextInterpolator $interpolator;

    /**
     * Create a new statement screen.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Context\CheckContextFactory|null  $contexts
     */
    public function __construct(

        /** The action the query is scoped to. */
        private readonly string $action,

        /** The model queried. */
        private readonly ResourceShape $shape,

        /** The subject the query is scoped for. */
        private readonly Subject $subject,

        /** Makes each check's context, and says which of its namespaces depend on the request alone; null for none. */
        private readonly ?CheckContextFactory $contexts = null,
    ) {
        $this->interpolator = new ContextInterpolator;
    }

    /**
     * Return the condition a row meets when the statement, one a check would
     * weigh, matches it, the condition it meets when the statement applies to
     * it (matches it or cannot be decided on it), and whether the statement has
     * a resource pattern that resolves. A statement that is refused, and one
     * that never bears on a row, matches and applies to none.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $reference
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @return array{string, string, bool}
     */
    public function terms(StatementReference $reference, Statement $statement, CheckContext $context): array
    {
        $refusal = $this->readRefusalOf($reference, $statement);

        if ($refusal !== null) {
            $this->refuse($refusal);

            return [QueryAuthorizer::NO_ROW, QueryAuthorizer::NO_ROW, false];
        }

        $patterns = $statement->notResources ?? $statement->resources;
        $resolved = $this->resolvedPatternsOf($patterns ?? [], new InterpolationScope($this->interpolator, null, $context));
        $targets  = $this->targetsOf($reference, $resolved);

        if ($targets === null) {
            return [QueryAuthorizer::NO_ROW, QueryAuthorizer::NO_ROW, $resolved !== []];
        }

        $isUnresolved = \count($resolved) < \count($patterns ?? []);
        $outcome      = self::isNamingAny($statement, $targets, $isUnresolved) ? $this->conditionsOf($statement, $context) : MatchOutcome::DOES_NOT_MATCH;

        if ($outcome === MatchOutcome::INVALID) {
            $this->refuse(Refusal::ofStatement(RefusalReason::INVALID_STATEMENT, $reference));
        }

        $terms = $outcome === MatchOutcome::DOES_NOT_MATCH || $outcome === MatchOutcome::INVALID
            ? [QueryAuthorizer::NO_ROW, QueryAuthorizer::NO_ROW]
            : $this->targetTerms($reference, $statement, $targets, $isUnresolved, $outcome);

        return [...$terms, $resolved !== []];
    }

    /**
     * Keep a refusal.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\Refusal  $refusal
     * @return void
     */
    public function refuse(Refusal $refusal): void
    {
        $this->refusals[$refusal->describe()] ??= $refusal;
    }

    /**
     * Return every refusal kept, in the order found.
     *
     * @return list<\SineMacula\Laravel\Authorization\Query\Refusal>
     */
    public function refusals(): array
    {
        return \array_values($this->refusals);
    }

    /**
     * Return which records each resolved pattern names, or null, keeping a
     * refusal, when one cannot be compared with a key.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $reference
     * @param  list<string>  $resolved
     * @return list<\SineMacula\Laravel\Authorization\Query\KeyTarget>|null
     */
    private function targetsOf(StatementReference $reference, array $resolved): ?array
    {
        $targets = \array_map(fn (string $pattern): ?KeyTarget => ResourcePatterns::targetOf($pattern, $this->shape->type), $resolved);

        if (\in_array(null, $targets, true)) {
            $this->refuse(Refusal::ofStatement(RefusalReason::RESOURCE_PATTERN, $reference));

            return null;
        }

        /** @var list<\SineMacula\Laravel\Authorization\Query\KeyTarget> */
        return $targets;
    }

    /**
     * Determine whether the statement's target can name any row, so `check()`
     * would go on to its conditions: one without resources names every row;
     * `resources` name a row when a pattern names any or cannot be resolved;
     * `not_resources` name the rows none of them covers, which is none only
     * when one names every row.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  list<\SineMacula\Laravel\Authorization\Query\KeyTarget>  $targets
     * @param  bool  $isUnresolved
     * @return bool
     */
    private static function isNamingAny(Statement $statement, array $targets, bool $isUnresolved): bool
    {
        $isEvery = \array_filter($targets, static fn (KeyTarget $target): bool => $target->isAll())   !== [];
        $isSome  = \array_filter($targets, static fn (KeyTarget $target): bool => !$target->isNone()) !== [];

        return match (true) {
            $statement->notResources !== null => !$isEvery,
            $statement->resources    !== null => $isSome || $isUnresolved,
            default                           => true,
        };
    }

    /**
     * Return how the statement's conditions bear on every row, assessed once by
     * `Statement::assess()` on the statement without its resources, which the
     * conditions never read.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome
     */
    private function conditionsOf(Statement $statement, CheckContext $context): MatchOutcome
    {
        $unbounded = new Statement($statement->effect, $statement->actions, null, $statement->conditions, $statement->sid, $statement->notActions, null, $statement->principals);

        return $unbounded->assess($this->action, null, $context, $this->interpolator)->outcome;
    }

    /**
     * Return the condition a row meets when the statement matches it and when
     * it applies to it, from what its patterns name and whether one could not
     * be resolved, its conditions holding or undecidable on every row; a
     * statement whose target holds on a row takes its conditions' outcome
     * there, and one whose target is undecidable on it is undecidable.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $reference
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  list<\SineMacula\Laravel\Authorization\Query\KeyTarget>  $targets
     * @param  bool  $isUnresolved
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome  $outcome
     * @return array{string, string}
     */
    private function targetTerms(StatementReference $reference, Statement $statement, array $targets, bool $isUnresolved, MatchOutcome $outcome): array
    {
        $covered = Conditions::any(\array_map(fn (KeyTarget $target): string => $this->keyCondition($reference, $target), $targets));
        $unknown = $isUnresolved ? QueryAuthorizer::EVERY_ROW : QueryAuthorizer::NO_ROW;

        [$matches, $applies] = match (true) {
            $statement->notResources !== null => [Conditions::all([Conditions::not($covered), Conditions::not($unknown)]), Conditions::not($covered)],
            $statement->resources    !== null => [$covered, Conditions::any([$covered, $unknown])],
            default                           => [QueryAuthorizer::EVERY_ROW, QueryAuthorizer::EVERY_ROW],
        };

        return [$outcome === MatchOutcome::MATCHES ? $matches : QueryAuthorizer::NO_ROW, $applies];
    }

    /**
     * Return the condition a row's key meets when the target names its record,
     * keeping a refusal when the key cannot be compared with it.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $reference
     * @param  \SineMacula\Laravel\Authorization\Query\KeyTarget  $target
     * @return string
     */
    private function keyCondition(StatementReference $reference, KeyTarget $target): string
    {
        [$condition, $reason] = KeyConditions::of($this->shape, $target);

        if ($reason !== null) {
            $this->refuse($reason === RefusalReason::RESOURCE_PATTERN ? Refusal::ofStatement($reason, $reference) : new Refusal($reason, null, null, $this->shape->keyName));
        }

        return $condition;
    }

    /**
     * Return the resource patterns, resolved as `check()` resolves them,
     * leaving out each whose reference cannot be resolved or resolves to a NUL
     * byte, which never reaches `fnmatch()`.
     *
     * @param  array<int, string>  $patterns
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return list<string>
     */
    private function resolvedPatternsOf(array $patterns, InterpolationScope $scope): array
    {
        $resolved = [];

        foreach ($patterns as $pattern) {
            $value = $scope->pattern($pattern);

            if ($value === null || \str_contains($value, "\0")) {
                continue;
            }

            $resolved[] = $value;
        }

        return $resolved;
    }

    /**
     * Return the refusal of a statement that reads what the scope cannot read
     * once for a query: an authentication requirement a checker not marked
     * `ScopeInvariant` would judge, the resource, or a namespace whose source
     * is not so marked; or null when it reads none of these.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $reference
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @return \SineMacula\Laravel\Authorization\Query\Refusal|null
     */
    private function readRefusalOf(StatementReference $reference, Statement $statement): ?Refusal
    {
        [$paths, $isRequiring] = $this->readsOf($statement);

        if ($isRequiring && $this->contexts?->isRequirementCheckScopeInvariant() === false) {
            return Refusal::ofStatement(RefusalReason::SCOPE_VARIANT_SOURCE, $reference, AuthenticationRequirement::OPERATOR);
        }

        $refusals = \array_filter(\array_map(fn (string $path): ?Refusal => $this->pathRefusalOf($reference, $path), $paths));

        return \reset($refusals) ?: null;
    }

    /**
     * Return the refusal of a statement reading the path, when it is the
     * resource's or a namespace whose source is not marked `ScopeInvariant`, or
     * null when the path is read once for a query.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $reference
     * @param  string  $path
     * @return \SineMacula\Laravel\Authorization\Query\Refusal|null
     */
    private function pathRefusalOf(StatementReference $reference, string $path): ?Refusal
    {
        $namespace = \explode('.', $path)[0];

        return match (true) {
            $namespace === 'resource'      => Refusal::ofStatement(RefusalReason::RESOURCE_NAMESPACE, $reference, $path),
            !$this->isFoldable($namespace) => Refusal::ofStatement(RefusalReason::SCOPE_VARIANT_SOURCE, $reference, $namespace),
            default                        => null,
        };
    }

    /**
     * Return every path the statement reads, each condition's key and the
     * references in its string operands and in its resource patterns, and
     * whether it states an authentication requirement, which the requirement
     * checker judges rather than any path.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @return array{list<string>, bool}
     */
    private function readsOf(Statement $statement): array
    {
        $paths       = [];
        $isRequiring = false;

        foreach (StatementValidator::conditionTests($statement->conditions) as $test) {
            if ($test['operator'] === AuthenticationRequirement::OPERATOR) {
                $isRequiring = true;

                continue;
            }

            $operand = \is_string($test['operand']) ? ContextInterpolator::references($test['operand']) : [];
            $paths   = [...$paths, $test['key'], ...$operand];
        }

        foreach ($statement->notResources ?? $statement->resources ?? [] as $pattern) {
            \array_push($paths, ...ContextInterpolator::references($pattern));
        }

        return [$paths, $isRequiring];
    }

    /**
     * Determine whether a namespace is read once for a query: its source
     * depends on the request alone. Without a context factory, a check reads
     * only what the caller passes and the subject's built-in keys.
     *
     * @param  string  $namespace
     * @return bool
     */
    private function isFoldable(string $namespace): bool
    {
        return $this->contexts?->isScopeInvariant($namespace, $this->subject) ?? true;
    }
}
