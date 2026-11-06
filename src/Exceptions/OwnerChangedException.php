<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a saved record would change what owns it, which is fixed once the
 * record is created.
 *
 * A role, permission or policy is owned by a tenant, or by the platform: every
 * grant of the record holds in the scope its tenant fixes, so to move one,
 * create it in the new tenant and grant it again. An inline policy also belongs
 * to one grantee, named by its `owner_type` and `owner_id` columns, and is
 * attached to that grantee alone: to give another grantee its statements,
 * create an inline policy for that grantee.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class OwnerChangedException extends \LogicException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $kind
     * @param  string  $name
     * @param  string  $ownerKind
     */
    public function __construct(

        /** The kind of record: `role`, `permission` or `policy`. */
        private readonly string $kind,

        /** The record's name. */
        private readonly string $name,

        /** What owns the record: `tenant`, or `grantee` for an inline policy. */
        private readonly string $ownerKind = 'tenant',
    ) {
        parent::__construct($ownerKind === 'grantee'
            ? "The grantee of inline {$kind} '{$name}' is fixed once it is created; create an inline {$kind} for the new grantee instead."
            : "The owner of {$kind} '{$name}' is fixed once it is created; create the {$kind} in the new owner instead.");
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
     * Return what owns the record: `tenant`, or `grantee` for an inline policy.
     *
     * @return string
     */
    public function getOwnerKind(): string
    {
        return $this->ownerKind;
    }
}
