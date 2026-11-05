<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a role or permission limited to one guard would be granted to a
 * grantee that declares another.
 *
 * A grantee declares its guard through `getAuthorizationGuard()`; one that
 * declares none, and a guard-agnostic role or permission, are compatible with
 * every guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GranteeGuardMismatchException extends \InvalidArgumentException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $kind
     * @param  string  $name
     * @param  string  $guard
     * @param  string  $granteeGuard
     */
    public function __construct(

        /** The kind of record: `role` or `permission`. */
        private readonly string $kind,

        /** The record's name. */
        private readonly string $name,

        /** The record's guard. */
        private readonly string $guard,

        /** The guard the grantee declares. */
        private readonly string $granteeGuard,
    ) {
        parent::__construct("Guard mismatch: {$kind} '{$name}' (guard '{$guard}') cannot be granted to a grantee of guard '{$granteeGuard}'.");
    }

    /**
     * Return the kind of record.
     *
     * @return string
     */
    public function getKind(): string
    {
        return $this->kind;
    }

    /**
     * Return the record's name.
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Return the record's guard.
     *
     * @return string
     */
    public function getGuard(): string
    {
        return $this->guard;
    }

    /**
     * Return the guard the grantee declares.
     *
     * @return string
     */
    public function getGranteeGuard(): string
    {
        return $this->granteeGuard;
    }
}
