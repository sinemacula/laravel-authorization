<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when the resolution cache store reports a write it did not make.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CacheWriteRefusedException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     */
    public function __construct()
    {
        parent::__construct('The resolution cache store refused a write.');
    }
}
