<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Console\Concerns\ResolvesIdentity;
use SineMacula\Laravel\Authorization\Facades\Authorization;

/**
 * Explain the evaluation trace for an identity, action, and optional
 * resource.
 *
 * Runs the full four-step evaluation (explicit deny, allow, RBAC,
 * implicit deny) and prints the verdict, reason, and ordered trace
 * so operators can diagnose authorization decisions from the CLI.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class WhyCanCommand extends Command
{
    use ResolvesIdentity;

    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:why-can
            {identity : Identity in morphType:key format (e.g. user:123)}
            {action : The action to evaluate}
            {resource? : Optional resource identifier}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Explain why an identity can or cannot perform an action';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        /** @var string $identityArg */
        $identityArg = $this->argument('identity');

        /** @var string $action */
        $action = $this->argument('action');

        /** @var string|null $resource */
        $resource = $this->argument('resource');

        $model = $this->resolveIdentity($identityArg);

        if ($model === null) {
            return self::FAILURE;
        }

        // @phpstan-ignore staticMethod.dynamicCall
        $result = Authorization::for($model)->evaluate($action, $resource);

        $verdict = $result->allowed ? 'ALLOWED' : 'DENIED';

        $this->line('');
        $this->line("  Result:   <fg={$this->verdictColor($result->allowed)}>{$verdict}</>");
        $this->line("  Reason:   {$result->reason->value}");
        $this->line("  Action:   {$action}");
        $this->line('  Resource: ' . ($resource ?? '(none)'));
        $this->line('');

        if ($result->trace !== []) {
            $this->line('  Trace:');

            foreach ($result->trace as $entry) {
                $this->line(\sprintf(
                    '    [%s] %s#%d — %s',
                    $entry['decision']->value,
                    $entry['policy'],
                    $entry['statement_index'],
                    $entry['reason'],
                ));
            }

            $this->line('');
        }

        return self::SUCCESS;
    }

    /**
     * Return the ANSI colour name for the verdict.
     *
     * @param  bool  $allowed
     * @return string
     */
    private function verdictColor(bool $allowed): string
    {
        return $allowed ? 'green' : 'red';
    }
}
