<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * The inputs a statement interpolates its patterns and operands against, and
 * tests its conditions against: the interpolator (null to leave `${…}` tokens
 * literal), the resource and the context of one check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InterpolationScope
{
    /** @var \SineMacula\Laravel\Authorization\Evaluation\CheckContext Context the conditions are tested against and `${…}` tokens read. */
    public CheckContext $context;

    /**
     * Create a new interpolation scope. A context given as an array is the
     * check's namespaces, already built.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null  $interpolator
     * @param  string|null  $resource
     * @param  array<array-key, mixed>|\SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     */
    public function __construct(

        /** Interpolator resolving `${…}` tokens; null leaves them literal. */
        public ?ContextInterpolator $interpolator = null,

        /** Identifier of the resource the check names, if any, which resource patterns are matched against. */
        public ?string $resource = null,

        // Context of the check; an array is its namespaces, already built.
        array|CheckContext $context = [],
    ) {
        $this->context = CheckContext::from($context);
    }

    /**
     * Interpolate a literal string, or null when a reference cannot be
     * resolved.
     *
     * @param  string  $subject
     * @return string|null
     */
    public function literal(string $subject): ?string
    {
        if ($this->interpolator === null) {
            return $subject;
        }

        return $this->interpolator->interpolate($subject, $this->context);
    }

    /**
     * Interpolate a glob pattern for `fnmatch()` without `FNM_NOESCAPE`, or
     * null when a reference cannot be resolved.
     *
     * @param  string  $pattern
     * @return string|null
     */
    public function pattern(string $pattern): ?string
    {
        if ($this->interpolator === null) {
            return ContextInterpolator::literalPattern($pattern);
        }

        return $this->interpolator->interpolatePattern($pattern, $this->context);
    }
}
