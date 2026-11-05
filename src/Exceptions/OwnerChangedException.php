<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a saved role, permission or policy would change the tenant that
 * owns it. The owner is fixed once the record is created, since every grant of
 * the record holds in the scope its owner fixes: to move one, create it in the
 * new owner and grant it again.
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
     */
    public function __construct(

        /** The kind of record: `role`, `permission` or `policy`. */
        private readonly string $kind,

        /** The record's name. */
        private readonly string $name,
    ) {
        parent::__construct("The owner of {$kind} '{$name}' is fixed once it is created; create the {$kind} in the new owner instead.");
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
}
