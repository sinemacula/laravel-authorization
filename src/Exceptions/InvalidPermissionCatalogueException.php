<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when the permission catalogue the application declares in code cannot
 * be synced: a name outside the package's name rules, an empty guard list on a
 * `#[Permission]` attribute, a guard that is not a non-empty string, a provider
 * returning something other than permission definitions, or two declarations of
 * one permission with different metadata.
 *
 * The exception names the declaration at fault (the enum case or the provider
 * class) and the reason, so `authorization:sync` can fail with a clear error
 * before anything is written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidPermissionCatalogueException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $source
     * @param  string  $reason
     */
    public function __construct(

        /** The declaration at fault: `Enum::CASE` or a provider class. */
        private readonly string $source,

        /** Human-readable explanation of why the declaration was refused. */
        private readonly string $reason,
    ) {
        parent::__construct("Invalid permission declared by {$source}: {$reason}", 500);
    }

    /**
     * Return the declaration at fault.
     *
     * @return string
     */
    public function getSource(): string
    {
        return $this->source;
    }

    /**
     * Return the reason the declaration was refused.
     *
     * @return string
     */
    public function getReason(): string
    {
        return $this->reason;
    }
}
