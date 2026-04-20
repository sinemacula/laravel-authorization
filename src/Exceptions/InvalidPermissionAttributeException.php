<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a `#[Permission]` attribute carries an invalid configuration that
 * cannot be expanded into a meaningful set of `(name, guard)` tuples.
 *
 * The only invalid shape the walker currently rejects is an explicit empty
 * `guards: []` array: `null` means guard-agnostic and any non-empty list
 * expands per guard, but an explicit empty list is ambiguous and almost
 * certainly a mistake.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class InvalidPermissionAttributeException extends \LogicException
{
    /**
     * Create a new exception instance for the supplied enum case.
     *
     * @param  class-string  $enumClass
     * @param  string  $caseName
     * @param  string  $reason
     */
    public function __construct(

        /** Fully-qualified enum class the offending case belongs to. */
        private readonly string $enumClass,

        /** Name of the enum case carrying the invalid attribute. */
        private readonly string $caseName,

        /** Human-readable explanation of why the attribute failed validation. */
        private readonly string $reason,

    ) {
        parent::__construct(\sprintf(
            'Invalid #[Permission] attribute on %s::%s: %s',
            $enumClass,
            $caseName,
            $reason,
        ));
    }

    /**
     * Return the enum class the offending case belongs to.
     *
     * @return class-string
     */
    public function getEnumClass(): string
    {
        return $this->enumClass;
    }

    /**
     * Return the enum case name that carries the invalid attribute.
     *
     * @return string
     */
    public function getCaseName(): string
    {
        return $this->caseName;
    }

    /**
     * Return the human-readable reason the attribute failed validation.
     *
     * @return string
     */
    public function getReason(): string
    {
        return $this->reason;
    }
}
