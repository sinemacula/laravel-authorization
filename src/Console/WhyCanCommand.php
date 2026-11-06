<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Console\Concerns\ResolvesIdentity;
use SineMacula\Laravel\Authorization\Facades\Authorization;

/**
 * Explain the evaluation trace for an identity, action, and optional resource.
 *
 * Runs the full staged evaluation in AUTHZ-7.1's order (the subject, resource
 * and tenant, the explicit denies, the guardrails, the permission boundaries,
 * the session caps, the allows and the implicit deny; see
 * docs/design/evaluation-order-and-deny-precedence.md) and prints the verdict,
 * reason, and ordered trace so operators can diagnose authorization decisions
 * from the CLI.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class WhyCanCommand extends Command
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
        $decision = Authorization::for($model)->check($action, $resource);
        $verdict  = $decision->isAllowed() ? 'ALLOWED' : 'DENIED';

        $this->line('');
        $this->line("  Result:   <fg={$this->verdictColor($decision->isAllowed())}>{$verdict}</>");
        $this->line('  Reason:   ' . ($decision->reason->value ?? '(none)'));
        $this->line("  Stage:    {$decision->stage->value}");
        $this->line("  Action:   {$action}");
        $this->line('  Resource: ' . ($resource ?? '(none)'));
        $this->line('');

        if ($decision->trace !== []) {
            $this->line('  Trace:');

            foreach ($decision->trace as $entry) {
                $this->line('    ' . $entry->toString());
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
