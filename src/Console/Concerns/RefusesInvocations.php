<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Concerns;

use SineMacula\Laravel\Authorization\Evaluation\ExplanationText;
use Symfony\Component\Console\Exception\ExceptionInterface as ConsoleException;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * How `authorization:why` and `authorization:review` refuse what they cannot
 * run: an invocation the console cannot bind to the signature, such as one with
 * an unknown option or a missing argument, and an option that takes a value but
 * was given none, are invalid invocations (exit 2), and every refusal is
 * written to the standard error alone, so the standard output holds nothing but
 * what the command prints.
 *
 * A refusal's control, format, bidirectional and line separator characters are
 * escaped as the explanation text escapes names, the whole of a message that is
 * not UTF-8 escaped so, and its markup escaped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Console\Command
 */
trait RefusesInvocations
{
    /**
     * Run the console command, refusing an invocation the console cannot bind
     * to its signature as an invalid invocation.
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
     * Return the options given, refusing one of those named that takes a value
     * but was given without one, which the console reads as if it were omitted.
     *
     * @param  list<string>  $valued
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException
     */
    protected function givenOptions(array $valued): array
    {
        foreach ($valued as $name) {
            if ($this->option($name) === null && $this->input->hasParameterOption('--' . $name, true)) {
                throw new \InvalidArgumentException("The --{$name} option must be given a value.");
            }
        }

        return $this->options();
    }

    /**
     * Write the error to the standard error and return the exit code, the error
     * escaped. The error style is left open, since the console closes it at the
     * end of the line.
     *
     * @param  string  $message
     * @param  int  $code
     * @return int
     */
    protected function refuse(string $message, int $code): int
    {
        $escaped = \preg_replace_callback('/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u', static fn (array $character): string => ExplanationText::bare($character[0]), $message);

        $this->output->getErrorStyle()->writeln('<error>' . OutputFormatter::escape($escaped ?? ExplanationText::bare($message)));

        return $code;
    }
}
