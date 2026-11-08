<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Thrown when a grant may widen an identity's scope but the identity behind its
 * grantee cannot be resolved, so the grant hook cannot be told whose scope
 * widens (AUTHZ-11.3).
 *
 * The grantee's model cannot be read, or the bound subject resolver's
 * `forUser()` throws, names no identity, or names the grantee as neither the
 * identity nor its subject. The grant is refused rather than written with its
 * hook skipped; nothing is written. The message names the grantee's type alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnresolvableRecipientException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \Throwable|null  $previous
     */
    public function __construct(

        /** The grantee whose identity could not be resolved. */
        public readonly Reference $grantee,

        // The failure that kept the identity from being resolved, if any.
        ?\Throwable $previous = null,
    ) {
        parent::__construct("The identity behind a grantee of type [{$grantee->type}] cannot be resolved, so a grant that may widen its scope is refused.", 0, $previous);
    }
}
