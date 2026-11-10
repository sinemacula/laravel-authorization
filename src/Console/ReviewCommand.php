<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Console\Concerns\RefusesInvocations;
use SineMacula\Laravel\Authorization\Console\Support\ReviewInvocation;
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Export an access review as JSON Lines (AUTHZ-11.6, N96, N97): who holds a
 * role, permission or policy, what a saved subject holds, what expires within a
 * window, what an actor last granted, or which grants show no observed use
 * since an instant (N94), in the scope the options name.
 *
 * The review runs on the trusted path (`AccessReview::trustedExport()`), as
 * scheduled system work, never as whoever is signed in to the console: the
 * console is a trusted operator surface. Its options are read strictly (see
 * `Support\ReviewInvocation`); the scope options mirror `authorization:why`'s
 * `--tenant`, with `--rooted-within` and `--everywhere` beside it.
 *
 * The export is written to the standard output, or with `--output` to a file,
 * which must not exist unless `--force` is given; nothing but the JSON Lines is
 * written to the standard output: a header, one line a row and a footer, each
 * one JSON object (see `Reviews\Support\JsonLinesExport`). The file is created
 * only when it does not exist, so a file made at the same instant is never
 * overwritten without `--force`.
 *
 * Exits 0 when the export is written; 2 for an invalid invocation (an unknown
 * option, a missing argument, an option given without its value or one the
 * query does not take, a reference, tenant, window or subject that cannot be
 * read or resolved, or an output file that exists or cannot be opened); and 1
 * when the review fails, after which the export has no footer. Errors go to the
 * standard error, name no value given, and are escaped as `authorization:why`
 * escapes its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ReviewCommand extends Command
{
    use RefusesInvocations;

    /** @var list<string> The options that take a value, refused when given without one. */
    private const array VALUED = ['tenant', 'rooted-within', 'application', 'from', 'until', 'actor', 'since', 'output'];

    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:review
                                    {query : The review: holders, holdings, expiring, granted_by or unused}
                                    {reference? : For holders, the role, permission or policy as type:key (e.g. role:1); for holdings, the saved subject as morphType:key}
                                    {--tenant= : Review what applies in the tenant, as morphType:key; the platform when no scope option is given}
                                    {--rooted-within= : Review the grants made in the tenant or below it, as morphType:key}
                                    {--everywhere : Review every stored grant}
                                    {--application= : none, any, or an application's name; none for a tenant or the platform when omitted, any otherwise}
                                    {--from= : For expiring, the start of the window, inclusive}
                                    {--until= : For expiring, the end of the window, exclusive}
                                    {--actor= : For granted_by, the actor as morphType:key}
                                    {--since= : For unused, the instant to look back to}
                                    {--direct-only : For holders, list the direct grants alone}
                                    {--output= : Write the JSON Lines to the file rather than the standard output}
                                    {--force : Overwrite the --output file when it exists}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Export an access review as JSON Lines, as trusted system work';

    /**
     * Execute the console command.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver  $subjects
     * @param  \SineMacula\Laravel\Authorization\Reviews\AccessReview  $reviews
     * @return int
     */
    public function handle(ConsoleSubjectResolver $subjects, AccessReview $reviews): int
    {
        try {
            $invocation = ReviewInvocation::of($this->arguments(), $this->givenOptions(self::VALUED));
            $query      = $invocation->query($subjects);
            $file       = self::fileFor($invocation);
        } catch (\InvalidArgumentException $exception) {
            return $this->refuse($exception->getMessage(), self::INVALID);
        }

        return $this->export($reviews, $query, $file);
    }

    /**
     * Export the review to the file, or to the standard output for none, or
     * refuse with the class of what the review threw. The file is closed when
     * its handle is released, as the command returns, whether or not the export
     * was written.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\AccessReview  $reviews
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  resource|null  $file
     * @return int
     */
    private function export(AccessReview $reviews, ReviewQuery $query, mixed $file): int
    {
        $sink = $file ?? function (string $line): void {
            $this->output->write($line, false, OutputInterface::OUTPUT_RAW);
        };

        try {
            $reviews->trustedExport($query, $sink);
        } catch (\Throwable $exception) {
            return $this->refuse('The review could not be exported (' . $exception::class . ').', self::FAILURE);
        }

        return self::SUCCESS;
    }

    /**
     * Open the file the invocation writes to, refusing one that exists unless
     * it is forced, or that cannot be opened; null for the standard output.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\ReviewInvocation  $invocation
     * @return resource|null
     *
     * @throws \InvalidArgumentException
     */
    private static function fileFor(ReviewInvocation $invocation): mixed
    {
        $path = $invocation->output;

        if ($path === null) {
            return null;
        }

        if (!$invocation->isForced && \file_exists($path)) {
            throw new \InvalidArgumentException('The --output file exists; give --force to overwrite it.');
        }

        try {
            $file = \fopen($path, $invocation->isForced ? 'wb' : 'xb');
        } catch (\Throwable) { // @phpstan-ignore catch.neverThrown (the application turns the warning of a file that cannot be opened into an exception)
            $file = false;
        }

        return $file === false ? throw new \InvalidArgumentException('The --output file could not be opened.') : $file;
    }
}
