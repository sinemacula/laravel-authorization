<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Diagnostics;

use Illuminate\Console\Command;
use Illuminate\Contracts\Console\Kernel;
use SineMacula\Laravel\Authorization\Console\CheckConfigurationCommand;

/**
 * A sibling package's command that runs `authorization:check` in the same
 * process, through the console kernel, on its own output, and ends with its
 * exit code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ComposingCheckCommand extends Command
{
    /** @var string The console command signature. */
    protected $signature = ComposingCommandProvider::COMMAND;

    /** @var string The console command description. */
    protected $description = 'Run the authorization check in the same process';

    /**
     * Run the check through the console kernel and end with its exit code.
     *
     * @param  \Illuminate\Contracts\Console\Kernel  $kernel
     * @return int
     */
    public function handle(Kernel $kernel): int
    {
        return $kernel->call(CheckConfigurationCommand::NAME, [], $this->output);
    }
}
