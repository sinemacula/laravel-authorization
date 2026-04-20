<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a role or permission save attempts to persist a name that falls
 * outside the allowed character set.
 *
 * Permission names double as `fnmatch` patterns during evaluation, so only
 * alphanumerics, underscores, hyphens, colons, and the `*` wildcard are
 * permitted; whitespace and the remaining glob metacharacters (`?`, `[`, `]`,
 * `{`, `}`) are rejected at save time to prevent an accidental
 * pattern-injection leak.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class InvalidAuthorizationNameException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $kind
     * @param  string  $name
     */
    public function __construct(

        /** Short label for the rejected entity ("role" or "permission"). */
        private readonly string $kind,

        /** Offending name attribute as it was supplied to the model. */
        private readonly string $name,

    ) {
        parent::__construct(
            "Invalid {$kind} name '{$name}': allowed characters are alphanumerics, ':', '_', '-', and '*'.",
            422,
        );
    }

    /**
     * Return the label identifying the entity whose name was rejected.
     *
     * @return string
     */
    public function getKind(): string
    {
        return $this->kind;
    }

    /**
     * Return the offending name attribute.
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }
}
