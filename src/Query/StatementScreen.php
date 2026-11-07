<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\InterpolationScope;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Evaluation\StatementEntries;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\StatementValidator;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Tells whether the statements one class of rows is decided from can be
 * compiled, before the pipeline weighs them (AUTHZ-10.2, N65, N68).
 *
 * A statement is material when a check would weigh it: it names the action,
 * and, for an allow (a guardrail's or a boundary's included), it applies to the
 * subject, as the policy evaluator tells (`PolicyEvaluator::isForSubject()`).
 * The scope compiles a query only when every material statement decides every
 * row of the class alike, so the decision the pipeline makes for the whole type
 * is the decision `check()` makes for each row. A material statement is
 * refused, with no pruning, when:
 *
 * - it reads the `resource` namespace, in a condition, an operand or a pattern
 *   (`resource_namespace`);
 * - it reads a namespace whose source is not marked `ScopeInvariant`, or states
 *   an authentication requirement the bound checker, not so marked, would judge
 *   (`scope_variant_source`);
 * - a resource pattern, resolved as `check()` resolves it, does not cover every
 *   record of the type (`resource_pattern`, see `ResourcePatterns`);
 * - it cannot be evaluated (`invalid_statement`).
 *
 * A pattern whose reference cannot be resolved, or resolves to a NUL byte,
 * decides every row alike, as `check()` finds it undecidable for each. The
 * screen also tells whether a material statement has a pattern that resolves,
 * which `fnmatch()` matches against each row's identifier, so the scope can
 * leave out the rows whose identifier it would refuse as too long.
 *
 * Every refusal is kept, once, across every class, so they are thrown together.
 *
 * @phpstan-import-type StatementEntry from \SineMacula\Laravel\Authorization\Evaluation\StatementEntries
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

    /** @var \SineMacula\Laravel\Authorization\Evaluation\StatementEntries Each policy's statements, worked out once. */
    private readonly StatementEntries $entries;

    /** @var \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator Resolves the patterns as `check()` does. */
    private readonly ContextInterpolator $interpolator;

    /**
     * Create a new statement screen.
     *
     * @param  string  $action
     * @param  string  $type
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Context\CheckContextFactory|null  $contexts
     */
    public function __construct(

        /** The action the query is scoped to. */
        private readonly string $action,

        /** The morph type of the model queried. */
        private readonly string $type,

        /** The subject the query is scoped for. */
        private readonly Subject $subject,

        /** Makes each check's context, and says which of its namespaces depend on the request alone; null for none. */
        private readonly ?CheckContextFactory $contexts = null,
    ) {
        $this->entries      = new StatementEntries;
        $this->interpolator = new ContextInterpolator;
    }

    /**
     * Screen every material statement of the sources, keeping a refusal for
     * each that cannot be compiled, and return those with a resource pattern
     * that resolves, which `fnmatch()` matches against each row's identifier.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckSources  $sources
     * @param  string  $identifier
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\StatementReference>
     */
    public function screen(CheckSources $sources, string $identifier): array
    {
        $patterned = [];

        foreach ($this->materialOf($sources) as [$reference, $statement]) {
            $resolved  = $this->screenStatement($reference, $statement, $sources->context, $identifier);
            $patterned = $resolved === [] ? $patterned : [...$patterned, $reference];
        }

        return $patterned;
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
     * Return every statement of the sources a check would weigh: each deny that
     * names the action, and each allow, a guardrail's and a boundary's
     * included, that names it and applies to the subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckSources  $sources
     * @return list<StatementEntry>
     */
    private function materialOf(CheckSources $sources): array
    {
        $gathered = $this->entries->of($sources->policies, $sources->boundaries, $sources->guardrails);
        $allows   = [$gathered['allow']];

        foreach ([...$gathered['guardrails'] ?? [], ...$gathered['boundaries']] as [$entries]) {
            $allows[] = $entries;
        }

        $isDenying = fn (array $entry): bool => $entry[1]->coversAction($this->action);
        $isWeighed = fn (array $entry): bool => $entry[1]->coversAction($this->action) && PolicyEvaluator::isForSubject($entry[0], $entry[1], $sources->context);

        return [...\array_values(\array_filter($gathered['deny'], $isDenying)), ...\array_values(\array_filter(\array_merge(...$allows), $isWeighed))];
    }

    /**
     * Screen one material statement, keeping a refusal when it cannot be
     * compiled, and return its resource patterns that resolve. Its patterns are
     * resolved only once nothing it reads is refused, so a refused namespace is
     * never built.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $reference
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @param  string  $identifier
     * @return list<string>
     */
    private function screenStatement(StatementReference $reference, Statement $statement, CheckContext $context, string $identifier): array
    {
        $refusal = $this->readRefusalOf($reference, $statement);

        if ($refusal !== null) {
            $this->refuse($refusal);

            return [];
        }

        $resolved = $this->resolvedPatternsOf($statement, new InterpolationScope($this->interpolator, $identifier, $context));
        $isWhole  = \array_filter($resolved, fn (string $pattern): bool => !ResourcePatterns::coversEveryRecord($pattern, $this->type)) === [];
        $outcome  = $isWhole ? $statement->assess($this->action, $identifier, $context, $this->interpolator)->outcome : null;
        $reason   = match ($outcome) {
            null                  => RefusalReason::RESOURCE_PATTERN,
            MatchOutcome::INVALID => RefusalReason::INVALID_STATEMENT,
            default               => null,
        };

        if ($reason !== null) {
            $this->refuse(Refusal::ofStatement($reason, $reference));
        }

        return $resolved;
    }

    /**
     * Return the statement's resource patterns, resolved as `check()` resolves
     * them, leaving out each whose reference cannot be resolved or resolves to
     * a NUL byte, which never reaches `fnmatch()`.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  \SineMacula\Laravel\Authorization\Evaluation\InterpolationScope  $scope
     * @return list<string>
     */
    private function resolvedPatternsOf(Statement $statement, InterpolationScope $scope): array
    {
        $resolved = \array_map(static fn (string $pattern): ?string => $scope->pattern($pattern), $statement->notResources ?? $statement->resources ?? []);

        return \array_values(\array_filter($resolved, static fn (?string $pattern): bool => $pattern !== null && !\str_contains($pattern, "\0")));
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
