<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Console\Support\WhyInvocation;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Explanation;
use SineMacula\Laravel\Authorization\Evaluation\ExplanationText;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Explain why a saved subject may or may not take an action (AUTHZ-11.5, N91).
 *
 * The subject, a `{morphType}:{key}` reference, is resolved by the bound
 * console subject resolver (see `Contracts\ConsoleSubjectResolver`) to its
 * principal and identity, never from whoever is signed in to the console. The
 * action is explained on the resource reference given, or on none, through
 * `Authorization::for()` and `explain()`, the one decision path (D22), in
 * explain mode (N89), with the scope the options name in place both as the
 * ambient grant scope and as the subject's (N71): the platform unless
 * `--tenant` names a tenant, never the tenant in place, and no application
 * unless `--application` names one. `--context` is a JSON object read as the
 * `input` namespace alone (N90). The decision is recorded and reported as any
 * explained check is, and the scope in place before is restored afterwards,
 * even when the check throws.
 *
 * The explanation is of the named subject under the given scope and console
 * context, without their browser session, so no authentication requirement is
 * met for it. It is printed once, as text by default, every name escaped, or
 * with `--format=json` as its versioned JSON alone, with no prose or styling on
 * the standard output. A key it reports missing is evidence of what the
 * decision found, not advice to supply it. It names policies, statements,
 * conditions, keys and grants, never a value, so the console is a trusted
 * operator surface; an application disclosing another subject's explanation
 * goes through `previewFor()`, which admits the caller first.
 *
 * Exits 0 when an explanation is produced, whether it allows or denies; 2 for
 * an invalid invocation (an option, the JSON, a reference, or a subject or
 * tenant that cannot be resolved); and 1 when the check fails, printing no
 * explanation. Errors go to the standard error, name no value given, and have
 * their markup and control characters escaped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class WhyCommand extends Command
{
    /** @var string What the text format says before the explanation. */
    public const string PREAMBLE = 'Explanation for the named subject under the given scope and console context, without their browser session:';

    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:why
                                    {subject : The saved subject in morphType:key format (e.g. user:1)}
                                    {action : The action to explain}
                                    {resource? : The resource reference check() takes (e.g. post:42); none explains a check without a resource}
                                    {--tenant= : The tenant as morphType:key; the platform when omitted}
                                    {--application= : The application; none when omitted}
                                    {--context= : A JSON object read as the input namespace}
                                    {--format=text : The output format: text or json}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Explain why a subject may or may not take an action, under a scope and console context';

    /**
     * Execute the console command.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver  $subjects
     * @param  \SineMacula\Laravel\Authorization\Context\CheckContextFactory  $contexts
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $authorization
     * @return int
     */
    public function handle(ConsoleSubjectResolver $subjects, CheckContextFactory $contexts, AuthorizationManager $authorization): int
    {
        try {
            $invocation = WhyInvocation::of($this->arguments(), $this->options(), $contexts->trustedNamespaces());
            $reference  = $this->argument('subject');
            $subject    = $subjects->resolve(\is_string($reference) ? $reference : '');
        } catch (\InvalidArgumentException $exception) {
            return $this->refuse($exception->getMessage(), self::INVALID);
        }

        try {
            $printed = self::printed($invocation->explain($authorization, $subject), $invocation->isJson);
        } catch (\Throwable $exception) {
            return $this->refuse('The explanation could not be produced (' . $exception::class . ').', self::FAILURE);
        }

        $this->output->writeln($printed, OutputInterface::OUTPUT_RAW);

        return self::SUCCESS;
    }

    /**
     * Return the explanation as it is printed: its versioned JSON alone, or its
     * text after the preamble.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Explanation  $explanation
     * @param  bool  $isJson
     * @return string
     *
     * @throws \JsonException
     */
    private static function printed(Explanation $explanation, bool $isJson): string
    {
        return $isJson
            ? \json_encode($explanation, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR)
            : self::PREAMBLE . "\n\n" . $explanation->toText();
    }

    /**
     * Write the error to the standard error, its markup and control characters
     * escaped, and return the exit code.
     *
     * @param  string  $message
     * @param  int  $code
     * @return int
     */
    private function refuse(string $message, int $code): int
    {
        $escaped = \preg_replace_callback('/[\x00-\x1F\x7F]|\xC2[\x80-\x9F]/', static fn (array $control): string => ExplanationText::bare($control[0]), $message) ?? '';

        $this->output->getErrorStyle()->writeln('<error>' . OutputFormatter::escape($escaped) . '</error>');

        return $code;
    }
}
