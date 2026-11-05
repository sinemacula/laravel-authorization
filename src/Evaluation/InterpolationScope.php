<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * The inputs a statement interpolates its patterns and operands against: the
 * interpolator (null to leave `${…}` tokens literal), the principal, the
 * resource and the context of one check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InterpolationScope
{
    /**
     * Create a new interpolation scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null  $interpolator
     * @param  object|null  $principal
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     */
    public function __construct(

        /** Interpolator resolving `${…}` tokens; null leaves them literal. */
        public ?ContextInterpolator $interpolator = null,

        /** Principal the check is about. */
        public ?object $principal = null,

        /** Resource the check names, if any. */
        public ?string $resource = null,

        /** Context the conditions are tested against. */
        public array $context = [],
    ) {}

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

        return $this->interpolator->interpolate($subject, $this->principal, $this->resource, $this->context);
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

        return $this->interpolator->interpolatePattern($pattern, $this->principal, $this->resource, $this->context);
    }
}
