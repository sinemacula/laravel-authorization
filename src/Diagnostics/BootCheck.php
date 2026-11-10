<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\BootCheckOutcome;

/**
 * The outcome of one check the diagnostic boot runs by building what a setting
 * names: whether it passed, failed or did not run, and, when it failed, the
 * class of what it threw, never its message.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class BootCheck
{
    /**
     * Create a new outcome.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\BootCheckOutcome  $outcome
     * @param  class-string<\Throwable>|null  $exception
     */
    public function __construct(

        /** The dotted path of the setting the check builds what it names. */
        public string $path,

        /** What became of the check. */
        public BootCheckOutcome $outcome,

        /** The class of the exception the check threw, when it failed, else null. */
        public ?string $exception = null,
    ) {}

    /**
     * Return the outcome of a check that did not run.
     *
     * @param  string  $path
     * @return self
     */
    public static function notRun(string $path): self
    {
        return new self($path, BootCheckOutcome::NOT_RUN);
    }

    /**
     * Return the outcome of a check that ran, failed when it threw.
     *
     * @param  string  $path
     * @param  class-string<\Throwable>|null  $exception
     * @return self
     */
    public static function ran(string $path, ?string $exception): self
    {
        return $exception === null ? new self($path, BootCheckOutcome::PASSED) : new self($path, BootCheckOutcome::FAILED, $exception);
    }
}
