<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Diagnostics;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;

/**
 * A sibling package's provider that declares a command of its own running
 * `authorization:check` in the same process.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ComposingCommandProvider extends ServiceProvider
{
    /** @var string The name of the command that composes the check. */
    public const string COMMAND = 'acme:doctor';

    /**
     * Declare the command that composes the check.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        Declarations::of($this->app)->composingCommand(self::COMMAND);
    }
}
