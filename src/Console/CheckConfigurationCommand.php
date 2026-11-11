<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use SineMacula\Laravel\Authorization\Console\Concerns\RefusesInvocations;
use SineMacula\Laravel\Authorization\Console\Support\ReportText;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigurationReport;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\ReportStatus;
use SineMacula\Laravel\Authorization\Diagnostics\Inspector;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Report the configuration the application runs with (AUTHZ-17.2, N113): every
 * setting, every seam and where its binding came from, the grant hooks in the
 * order they run, the connection, and how the package is wired into the
 * application, with every issue the configuration's checks find.
 *
 * The report is built by `Diagnostics\Inspector` without building any seam,
 * connecting to anything or running a query, so it is safe before migrations
 * have run. Run from the console, or by a command a sibling package declares as
 * running it in the same process, the application boots the package for
 * diagnosis (see `Diagnostics\DiagnosticMode`): a broken configuration no
 * longer stops the boot, every operation of the package refuses instead, and
 * the report holds every issue that boot found, with what became of each check
 * it runs by building what a setting names (a context source, an attribute
 * provider, the cache store): checked at boot, failed at boot, or not run, as
 * the structural check found an issue first. On an application that booted
 * otherwise, the configuration is checked again, collecting every issue rather
 * than stopping at the first, by its structural checks alone, and what the boot
 * checks by building something is shown as checked at boot.
 *
 * It is printed as text by default, one line per issue first, then a section
 * each for the settings, the seams, the grant hooks, the connection and the
 * integrations, and a last line with the outcome; or, with `--format=json`, as
 * the report's versioned JSON alone (see `ConfigurationReport::toArray()`),
 * with no prose or styling on the standard output. Neither shows a credential,
 * a URL, a context value, a value the report does not allow, or an exception's
 * message.
 *
 * Exits 0 when every check passed; 1 when a setting is refused; 3 when the
 * report could not be completed and no setting is refused; and 2 for an invalid
 * invocation (an unknown option, or a format other than `text` or `json`). A
 * failure inside the command itself is caught and ends it with 1 for a refused
 * configuration or 3 for anything else, naming the exception's class alone, so
 * a command calling it in-process never sees it throw. The console's own
 * bootstrap, and a deferred provider loaded before the command runs, are
 * outside it, so it cannot catch what they throw: a caller that boots an
 * application itself to call it must turn the diagnostic switch on before the
 * application boots (see `Diagnostics\DiagnosticMode::enable()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CheckConfigurationCommand extends Command
{
    use RefusesInvocations;

    /** @var string The console command's name. */
    public const string NAME = 'authorization:check';

    /** @var int How the JSON is encoded: indented, with slashes as they are and any byte that is not UTF-8 replaced. */
    private const int JSON = \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_INVALID_UTF8_SUBSTITUTE | \JSON_THROW_ON_ERROR;

    /** @var list<string> The options that take a value, refused when given without one. */
    private const array VALUED = ['format'];

    /** @var string The console command signature. */
    protected $signature = self::NAME . <<<'EOD'

                                    {--format=text : The output format: text or json}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Report the authorization configuration the application runs with';

    /**
     * Execute the console command.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return int
     */
    public function handle(ConfigRepository $config): int
    {
        try {
            $isJson = self::isJson($this->givenOptions(self::VALUED)['format'] ?? null);
        } catch (\InvalidArgumentException $exception) {
            return $this->refuse($exception->getMessage(), self::INVALID);
        }

        try {
            return $this->report((new Inspector($this->laravel, $config))->inspect(), $isJson);
        } catch (\Throwable $exception) {
            return $this->failed($exception);
        }
    }

    /**
     * Print the report and return the exit code its status gives.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\ConfigurationReport  $report
     * @param  bool  $isJson
     * @return int
     *
     * @throws \JsonException
     */
    private function report(ConfigurationReport $report, bool $isJson): int
    {
        if ($isJson) {
            $this->output->writeln(\json_encode($report->toArray(), self::JSON), OutputInterface::OUTPUT_RAW);
        } else {
            $this->output->writeln(ReportText::lines($report));
        }

        return $report->status->exitCode();
    }

    /**
     * Report a failure of the command itself on the standard error, naming its
     * class alone, and return 1 for a refused configuration, else 3.
     *
     * @param  \Throwable  $exception
     * @return int
     */
    private function failed(\Throwable $exception): int
    {
        $status = $exception instanceof InvalidAuthorizationConfigException ? ReportStatus::REFUSED : ReportStatus::INCOMPLETE;

        return $this->refuse(\rtrim(ReportText::CONCLUSIONS[$status->value], '.') . ' (' . $exception::class . ').', $status->exitCode());
    }

    /**
     * Determine whether the format option asks for JSON, refusing any format
     * but `text` and `json`.
     *
     * @param  mixed  $format
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private static function isJson(mixed $format): bool
    {
        return match ($format) {
            'json'       => true,
            'text', null => false,
            default      => throw new \InvalidArgumentException('The --format option must be text or json.'),
        };
    }
}
