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
use SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException;
use SineMacula\Laravel\Authorization\Subject;
use Symfony\Component\Console\Exception\ExceptionInterface as ConsoleException;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Explain why a saved subject may or may not take an action (AUTHZ-11.5, N91).
 *
 * The subject, a `{morphType}:{key}` reference, is resolved by the bound
 * console subject resolver (see `Contracts\ConsoleSubjectResolver`) to its
 * principal and identity, never from whoever is signed in to the console. The
 * action is explained on the resource given, or on none, through
 * `Authorization::for()` and `explain()`, the one decision path (D22), in
 * explain mode (N89), with the scope the options name in place both as the
 * ambient grant scope and as the subject's (N71): the platform unless
 * `--tenant` names a tenant, never the tenant in place, and no application
 * unless `--application` names one. `--context` is a JSON object read as the
 * `input` namespace alone (N90). A `{morphType}:{key}` resource names that
 * record and `{morphType}:*` its type alone, passed to the check as it takes
 * them, so the record's tenant, resource policies and attribute provider apply
 * as in any check; any other resource, or any with `--opaque`, is an opaque
 * identifier (N92). The decision is recorded and reported as any explained
 * check is, and the scope in place before is restored afterwards, even when the
 * check throws.
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
 * an invalid invocation (an unknown option, a missing argument, an option given
 * without its value, the JSON, a reference, or a subject or tenant that cannot
 * be resolved, whatever failed resolving it); and 1 when the check fails,
 * printing no explanation. Errors go to the standard error, name no value
 * given, and have their markup, control, format and bidirectional characters
 * escaped, as is any byte that is not UTF-8.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class WhyCommand extends Command
{
    /** @var string What the text format says before the explanation. */
    public const string PREAMBLE = 'Explanation for the named subject under the given scope and console context, without their browser session:';

    /** @var list<string> The options that take a value, refused when given without one. */
    private const array VALUED = ['tenant', 'application', 'context', 'format'];

    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:why
                                    {subject : The saved subject in morphType:key format (e.g. user:1)}
                                    {action : The action to explain}
                                    {resource? : A record as type:id (e.g. post:42), a type alone as type:*, or an opaque identifier; none checks without one}
                                    {--tenant= : The tenant as morphType:key; the platform when omitted}
                                    {--application= : The application; none when omitted}
                                    {--context= : A JSON object read as the input namespace}
                                    {--format=text : The output format: text or json}
                                    {--opaque : Check the resource as an opaque identifier, even when it holds a colon}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Explain why a subject may or may not take an action, under a scope and console context';

    /**
     * Run the console command, refusing an invocation the console cannot bind
     * to its signature, such as one with an unknown option or a missing
     * argument, as an invalid invocation.
     *
     * @param  \Symfony\Component\Console\Input\InputInterface  $input
     * @param  \Symfony\Component\Console\Output\OutputInterface  $output
     * @return int
     */
    #[\Override]
    public function run(InputInterface $input, OutputInterface $output): int
    {
        try {
            return parent::run($input, $output);
        } catch (ConsoleException $exception) {
            return $this->refuse($exception->getMessage(), self::INVALID);
        }
    }

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
            $invocation = WhyInvocation::of($this->arguments(), $this->givenOptions(), $contexts->trustedNamespaces());
            $subject    = self::subject($subjects, $this->argument('subject'));
        } catch (\InvalidArgumentException $exception) {
            return $this->refuse($exception->getMessage(), self::INVALID);
        }

        return $this->explain($invocation, $subject, $authorization);
    }

    /**
     * Explain the invocation's check about the subject and print it, or refuse
     * with the class of what the check threw, printing no explanation.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\WhyInvocation  $invocation
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $authorization
     * @return int
     */
    private function explain(WhyInvocation $invocation, Subject $subject, AuthorizationManager $authorization): int
    {
        try {
            $printed = self::printed($invocation->explain($authorization, $subject), $invocation->isJson);
        } catch (\Throwable $exception) {
            return $this->refuse('The explanation could not be produced (' . $exception::class . ').', self::FAILURE);
        }

        $this->output->writeln($printed, OutputInterface::OUTPUT_RAW);

        return self::SUCCESS;
    }

    /**
     * Return the options given, refusing one that takes a value but was given
     * without one, which the console reads as if it were omitted.
     *
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function givenOptions(): array
    {
        foreach (self::VALUED as $name) {
            if ($this->option($name) === null && $this->input->hasParameterOption('--' . $name, true)) {
                throw new \InvalidArgumentException("The --{$name} option must be given a value.");
            }
        }

        return $this->options();
    }

    /**
     * Resolve the subject the reference names through the console subject
     * resolver, refusing it, without naming the failure, when the resolver
     * fails other than by refusing it.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver  $subjects
     * @param  mixed  $reference
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException
     */
    private static function subject(ConsoleSubjectResolver $subjects, mixed $reference): Subject
    {
        try {
            return $subjects->resolve(\is_string($reference) ? $reference : '');
        } catch (\Throwable $exception) {
            throw self::refusal($exception);
        }
    }

    /**
     * Return the refusal of a subject the console subject resolver failed to
     * resolve: the resolver's own refusal, or one naming neither the reference
     * nor the failure.
     *
     * @param  \Throwable  $failure
     * @return \SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException
     */
    private static function refusal(\Throwable $failure): UnresolvedSubjectException
    {
        return $failure instanceof UnresolvedSubjectException ? $failure : UnresolvedSubjectException::unresolvable($failure);
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
     * Write the error to the standard error and return the exit code: its
     * control, format, bidirectional and line separator characters escaped as
     * the text renderer escapes names, the whole of a message that is not UTF-8
     * escaped so, and its markup escaped. The error style is left open, since
     * the console closes it at the end of the line.
     *
     * @param  string  $message
     * @param  int  $code
     * @return int
     */
    private function refuse(string $message, int $code): int
    {
        $escaped = \preg_replace_callback('/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u', static fn (array $character): string => ExplanationText::bare($character[0]), $message);

        $this->output->getErrorStyle()->writeln('<error>' . OutputFormatter::escape($escaped ?? ExplanationText::bare($message)));

        return $code;
    }
}
