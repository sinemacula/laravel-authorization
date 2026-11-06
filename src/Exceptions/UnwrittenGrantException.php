<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a permission boundary or a resource policy attachment could not
 * be written, so that nothing is reported as set that is not.
 *
 * The row is inserted with insert-or-ignore and read back under a row lock on
 * the write connection. When the insert is ignored and no row is there to read
 * back, even once the write is tried again, the call refuses rather than report
 * an outcome no row bears out: its transaction rolls back and no event is
 * dispatched. A policy deleted at the same moment is refused with
 * `InvalidGrantTargetException` instead; this is thrown when the policy is
 * still there, as when concurrent calls keep removing the row as it is written.
 * Retrying the call is safe.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnwrittenGrantException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $grant
     */
    public function __construct(

        /** What was not written, such as `boundary of user:user-1`. */
        private readonly string $grant,
    ) {
        parent::__construct("The {$grant} was not written: no row was stored or found once the write was tried again; retry the call.");
    }

    /**
     * Return what was not written.
     *
     * @return string
     */
    public function getGrant(): string
    {
        return $this->grant;
    }
}
