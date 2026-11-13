<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Enums\BreakGlassRefusal;

/**
 * Thrown when a break-glass activation, or a surrender, is refused before
 * anything is written (AUTHZ-11.7): break-glass is disabled, or the call breaks
 * one of its limits, each named by its reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BreakGlassRefusedException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\BreakGlassRefusal  $reason
     * @param  string  $message
     */
    public function __construct(

        /** Why the call was refused. */
        private readonly BreakGlassRefusal $reason,

        // What was refused, in one sentence.
        string $message,
    ) {
        parent::__construct($message);
    }

    /**
     * Return why the call was refused.
     *
     * @return \SineMacula\Laravel\Authorization\Enums\BreakGlassRefusal
     */
    public function getReason(): BreakGlassRefusal
    {
        return $this->reason;
    }
}
