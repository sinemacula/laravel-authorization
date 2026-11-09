<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * The context of one check: nested namespaces (`authentication`, `request`,
 * `environment`, `subject`, `resource`, `input` and any an application source
 * adds), each read as a dot path, segment by segment (N24).
 *
 * A namespace is given already built (the caller's `input`) or built by a
 * builder the first time a statement of the check reads it, and at most once
 * for the check, even when its builder throws: the namespaces no statement
 * reads are never built. A builder returns its namespaces' values keyed by
 * namespace, and may build several namespaces at once (the authentication
 * context builds `authentication` and any `mfa` or `sso` namespace it
 * contributes); a namespace it leaves out is absent, so its keys are missing.
 * Build a new context for every check, so no value outlives the check that read
 * it.
 *
 * A path is never a literal flat key: `request.ip` reads the `ip` key of the
 * `request` namespace, and a top-level key named `request.ip` is never read.
 * The one resolver keeps a missing key (an absent namespace or key, a segment
 * read through a value that is not an array, an empty segment) apart from a key
 * present with a null value, which conditions and `${…}` interpolation alike
 * rely on.
 *
 * The reserved key `authentication` an authentication requirement tests is
 * never read as a path: the context judges each requirement through its
 * requirement check, for the check's subject and session, and records what the
 * decision may be reused for. A context built without one finds every
 * requirement unmet.
 *
 * The check's subject answers whether a resource policy's `principals` name it
 * (see `PrincipalSelectors`); a context built without it is named by none, so
 * no resource policy's allow applies.
 *
 * A context an explained check reads through records the evidence the
 * explanation needs (N89): each `${…}` reference it could not resolve, by key,
 * which the statement reading it takes once its test is assessed. Any other
 * context records nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CheckContext
{
    /** @var array<array-key, mixed> The namespaces built so far, keyed by name. */
    private array $namespaces;

    /** @var array<string, \Closure(): array<array-key, mixed>> The builders not yet run, by each namespace they build. */
    private array $builders;

    /** @var \SineMacula\Laravel\Authorization\Evaluation\RequirementCheck Judges the check's authentication requirements. */
    private readonly RequirementCheck $requirements;

    /** @var \SineMacula\Laravel\Authorization\Evaluation\PrincipalSelectors|null Tells whether a resource policy's selectors name the check's subject; null names no one. */
    private readonly ?PrincipalSelectors $principals;

    /** @var bool Whether the context records the evidence an explanation needs; false for an everyday check. */
    private bool $isExplaining = false;

    /** @var list<string> The `${…}` references that could not be resolved since they were last taken, recorded while explaining. */
    private array $unresolved = [];

    /** @var array{list<\SineMacula\Laravel\Authorization\Evaluation\ConditionResult>|null, list<string>}|null The condition tests of the statement last assessed, null when its target did not match, with its resource patterns' unresolved references, until they are taken; null for none. */
    private ?array $assessment = null;

    /**
     * Create a new check context.
     *
     * A namespace given already built is never built again, so a builder for it
     * is ignored.
     *
     * @param  array<array-key, mixed>  $namespaces
     * @param  array<string, \Closure(): array<array-key, mixed>>  $builders
     * @param  \SineMacula\Laravel\Authorization\Evaluation\RequirementCheck|null  $requirements
     * @param  \SineMacula\Laravel\Authorization\Evaluation\PrincipalSelectors|null  $principals
     */
    public function __construct(array $namespaces = [], array $builders = [], ?RequirementCheck $requirements = null, ?PrincipalSelectors $principals = null)
    {
        $this->namespaces   = $namespaces;
        $this->builders     = \array_diff_key($builders, $namespaces);
        $this->requirements = $requirements ?? new RequirementCheck;
        $this->principals   = $principals;
    }

    /**
     * Record, from now on, the evidence an explanation needs.
     *
     * @return void
     */
    public function explain(): void
    {
        $this->isExplaining = true;
    }

    /**
     * Determine whether the context records the evidence an explanation needs.
     *
     * @return bool
     */
    public function isExplaining(): bool
    {
        return $this->isExplaining;
    }

    /**
     * Note a `${…}` reference that could not be resolved, by its key, when the
     * context records evidence; otherwise do nothing.
     *
     * @param  string  $reference
     * @return void
     */
    public function noteUnresolved(string $reference): void
    {
        if (!$this->isExplaining) {
            return;
        }

        $this->unresolved[] = $reference;
    }

    /**
     * Note a `${…}` reference by its key when it cannot be resolved, its value
     * missing or not a scalar, as the interpolator does, while explaining, for
     * each reference after the first of a string that could not be resolved. A
     * reference into a namespace no statement has read yet is not looked up, so
     * noting it never builds a namespace, nor asks its provider.
     *
     * @param  string  $reference
     * @return void
     */
    public function noteIfUnresolved(string $reference): void
    {
        if (isset($this->builders[\explode('.', $reference)[0]]) || \is_scalar($this->lookup($reference)[1])) {
            return;
        }

        $this->unresolved[] = $reference;
    }

    /**
     * Return each `${…}` reference noted as unresolved since they were last
     * taken, in order, and forget them.
     *
     * @return list<string>
     *
     * @phpstan-impure
     */
    public function takeUnresolved(): array
    {
        $unresolved       = $this->unresolved;
        $this->unresolved = [];

        return $unresolved;
    }

    /**
     * Note the condition tests a statement just made, with what each found, or
     * none for a statement whose target did not match, and the keys of its
     * resource patterns' references that could not be resolved, for the
     * evaluator to take into the statement's step.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\ConditionResult>|null  $tests
     * @param  list<string>  $unresolved
     * @return void
     */
    public function noteAssessment(?array $tests, array $unresolved): void
    {
        $this->assessment = [$tests, $unresolved];
    }

    /**
     * Return the condition tests the statement last assessed noted, with its
     * unresolved resource pattern references, and forget them: no tests when it
     * noted none, as a statement whose target does not match notes none, and no
     * references when nothing was noted.
     *
     * @return array{list<\SineMacula\Laravel\Authorization\Evaluation\ConditionResult>|null, list<string>}
     *
     * @phpstan-impure
     */
    public function takeAssessment(): array
    {
        $assessment       = $this->assessment ?? [null, []];
        $this->assessment = null;

        return $assessment;
    }

    /**
     * Return the context itself, or a context whose namespaces are the given
     * array, already built.
     *
     * @param  array<array-key, mixed>|self  $context
     * @return self
     */
    public static function from(array|self $context): self
    {
        return $context instanceof self ? $context : new self($context);
    }

    /**
     * Read a dot path, such as `request.ip`.
     *
     * Returns whether the key is present and its value, which is null both for
     * a missing key and for a key present with a null value.
     *
     * @param  string  $path
     * @return array{bool, mixed}
     */
    public function lookup(string $path): array
    {
        return $this->find(\explode('.', $path));
    }

    /**
     * Read a path given as its segments, the namespace first, building the
     * namespace if no statement of the check has read it yet.
     *
     * Returns whether the key is present and its value, which is null both for
     * a missing key and for a key present with a null value.
     *
     * @param  list<string>  $segments
     * @return array{bool, mixed}
     */
    public function find(array $segments): array
    {
        [$isPresent, $value] = $this->namespaceOf($segments[0] ?? '');

        for ($index = 1, $count = \count($segments); $isPresent && $index < $count; $index++) {
            $segment   = $segments[$index];
            $isPresent = \is_array($value) && $segment !== '' && \array_key_exists($segment, $value);
            $value     = $isPresent ? $value[$segment] : null;
        }

        return [$isPresent, $value];
    }

    /**
     * Assess an authentication requirement for the check's subject and session:
     * it holds when met, definitely does not hold when unmet, and is
     * undecidable when the checker fails.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    public function assessRequirement(AuthenticationRequirement $requirement): MatchResult
    {
        return $this->requirements->assess($requirement);
    }

    /**
     * Determine whether any of a resource policy's `principals` selectors names
     * the check's subject: its principal or identity by reference, or a role it
     * holds in the scope the check is decided in. A context built without the
     * subject's selectors is named by none.
     *
     * @param  array<int, string>  $selectors
     * @return bool
     */
    public function isSubjectNamedBy(array $selectors): bool
    {
        return $this->principals?->isNamedByAny($selectors) ?? false;
    }

    /**
     * Return how long a decision made on the context may be reused, or null
     * when it read no authentication requirement.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness|null
     */
    public function requirementFreshness(): ?RequirementFreshness
    {
        return $this->requirements->freshness();
    }

    /**
     * Return whether the namespace is present and its values, building it on
     * the first read.
     *
     * @param  string  $namespace
     * @return array{bool, mixed}
     */
    private function namespaceOf(string $namespace): array
    {
        if (isset($this->builders[$namespace])) {
            $this->build($this->builders[$namespace]);
        }

        $isPresent = $namespace !== '' && \array_key_exists($namespace, $this->namespaces);

        return [$isPresent, $isPresent ? $this->namespaces[$namespace] : null];
    }

    /**
     * Run a builder once and keep every namespace it builds, leaving absent
     * those it was to build but left out.
     *
     * The builder is dropped before it runs, so one that throws is never run
     * again for the check: the failure aborts the check, and its namespaces
     * stay absent rather than being built on a later read.
     *
     * @param  \Closure(): array<array-key, mixed>  $builder
     * @return void
     */
    private function build(\Closure $builder): void
    {
        $namespaces = \array_keys($this->builders, $builder, true);

        foreach ($namespaces as $namespace) {
            unset($this->builders[$namespace]);
        }

        $built = $builder();

        foreach ($namespaces as $namespace) {
            if (!\array_key_exists($namespace, $built)) {
                continue;
            }

            $this->namespaces[$namespace] = $built[$namespace];
        }
    }
}
