<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a policy is attached to, or detached from, a value that names no
 * resource it can be attached to (AUTHZ-7.3): an unsaved model, an opaque
 * identifier, a pair that is not a type and a key, or a type or key longer than
 * the table stores.
 *
 * A resource policy is attached to one record of a type, or to the whole type,
 * so the resource must have a type. The value comes from the calling code, so
 * this is a programming error rather than a client-facing outcome.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidResourceException extends \InvalidArgumentException
{
    /**
     * Create a new exception instance.
     *
     * @param  mixed  $resource
     */
    public function __construct(mixed $resource)
    {
        parent::__construct('A resource policy is attached to a record or a resource type, not ' . \get_debug_type($resource) . '.');
    }
}
