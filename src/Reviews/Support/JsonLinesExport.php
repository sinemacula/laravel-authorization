<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authorization\Exceptions\ReviewExportException;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;

/**
 * The JSON Lines an access review is exported as (N97): one JSON object a line,
 * each ended by a line feed, in UTF-8, version 1.
 *
 * - The first line is the header: `record` `header`, the row schema `version`,
 *   the `query` kind, the `scope` (its selection, its tenant or null, and its
 *   application selection and name), the review's instant (`reviewed_at`), when
 *   the scan began (`scan_started_at`), and the consistency mode, `live`: the
 *   export is a live scan, not a snapshot.
 * - Then one line a row: `record` `row` and the row's versioned shape (see
 *   `ReviewRow::toArray()`), references alone, in the review's order.
 * - The last line is the footer: `record` `footer`, the `version`, how many
 *   `rows` were written, when the scan ended (`scan_ended_at`), and whether it
 *   is `complete`: false only for an identity's holdings whose directory could
 *   not list every principal.
 *
 * Each instant is in UTC, to the microsecond; a row's are to the second, as
 * stored. The output is deterministic: the same rows, read at the same
 * instants, give the same bytes. Each line is encoded with its keys in a fixed
 * order, slashes and Unicode left unescaped, the line and paragraph separators
 * escaped, and invalid UTF-8 refused with `JsonException` rather than replaced.
 * An export that stops before its end, refused or failing, has no footer, so a
 * reader can tell it is incomplete; a stream that takes none of a line fails it
 * with `Exceptions\ReviewExportException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class JsonLinesExport
{
    /** @var string The consistency mode of every export: a live paged scan. */
    public const string CONSISTENCY = 'live';

    /** @var int The flags each line is encoded with. */
    private const int FLAGS = \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE;

    /** @var string The format of an export's own instants. */
    private const string INSTANT = 'Y-m-d\TH:i:s.u\Z';

    /** @var int How many rows have been written. */
    private int $written = 0;

    /** @var bool Whether every page so far listed every principal of the identity reviewed. */
    private bool $isComplete = true;

    /**
     * Create a new export into the sink.
     *
     * @param  \Closure(string): void  $sink
     */
    private function __construct(

        /** What each line is written to. */
        private readonly \Closure $sink,
    ) {}

    /**
     * Return an export into the sink: a writable stream resource, each line
     * written to it whole however little each write takes, a stream that takes
     * none of what is left of a line refused with `ReviewExportException`; or a
     * callback given each line.
     *
     * @param  mixed  $sink
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function into(mixed $sink): self
    {
        if (\is_callable($sink)) {
            return new self(static function (string $line) use ($sink): void {
                $sink($line);
            });
        }

        if (!\is_resource($sink) || \get_resource_type($sink) !== 'stream') {
            throw new \InvalidArgumentException('An access review is exported to a writable stream resource or a callback.');
        }

        return new self(static function (string $line) use ($sink): void {
            while ($line !== '') {
                $written = \fwrite($sink, $line);
                $line    = $written === false || $written === 0 ? throw ReviewExportException::unwritable() : \substr($line, $written);
            }
        });
    }

    /**
     * Write the export of the query from its pages, as each is read: the header
     * once the first page is read, its rows, every later page's, then the
     * footer; and return how many rows were written. What reading a page
     * throws, such as a refused admission, and a stream sink's
     * `ReviewExportException` are thrown on, with no footer.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  iterable<\SineMacula\Laravel\Authorization\Reviews\Support\PageRead>  $pages
     * @param  \Carbon\CarbonImmutable  $startedAt
     * @return int
     *
     * @throws \JsonException
     */
    public function write(ReviewQuery $query, iterable $pages, CarbonImmutable $startedAt): int
    {
        $isFirst = true;

        foreach ($pages as $page) {
            if ($isFirst) {
                $this->line(self::header($query, $page->at, $startedAt));
            }

            $isFirst = false;

            $this->rows($page);
        }

        $this->line([
            'record'        => 'footer',
            'version'       => ReviewRow::VERSION,
            'rows'          => $this->written,
            'scan_ended_at' => self::instant(CarbonImmutable::now('UTC')),
            'complete'      => $this->isComplete,
        ]);

        return $this->written;
    }

    /**
     * Return the header of the export of the query.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \Carbon\CarbonImmutable  $reviewedAt
     * @param  \Carbon\CarbonImmutable  $startedAt
     * @return array<string, mixed>
     */
    public static function header(ReviewQuery $query, CarbonImmutable $reviewedAt, CarbonImmutable $startedAt): array
    {
        $scope  = $query->scope;
        $tenant = $scope->tenant;

        return [
            'record'  => 'header',
            'version' => ReviewRow::VERSION,
            'query'   => $query->kind->value,
            'scope'   => [
                'selection'   => $scope->selection->value,
                'tenant'      => $tenant === null ? null : ['type' => $tenant->type, 'id' => $tenant->id],
                'application' => ['selection' => $scope->application->selection(), 'name' => $scope->application->application],
            ],
            'reviewed_at'     => self::instant($reviewedAt),
            'scan_started_at' => self::instant($startedAt),
            'consistency'     => self::CONSISTENCY,
        ];
    }

    /**
     * Return the line of the record: its JSON and a line feed.
     *
     * @param  array<string, mixed>  $record
     * @return string
     *
     * @throws \JsonException
     */
    public static function encode(array $record): string
    {
        return \json_encode($record, self::FLAGS) . "\n";
    }

    /**
     * Write the page's rows, one line each, and note whether it was complete.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\PageRead  $page
     * @return void
     *
     * @throws \JsonException
     */
    private function rows(PageRead $page): void
    {
        $this->isComplete = $this->isComplete && $page->isComplete;

        foreach ($page->rows as $row) {
            $this->line(['record' => 'row', ...$row->toArray()]);
            $this->written++;
        }
    }

    /**
     * Write the record as one line to the sink.
     *
     * @param  array<string, mixed>  $record
     * @return void
     *
     * @throws \JsonException
     */
    private function line(array $record): void
    {
        ($this->sink)(self::encode($record));
    }

    /**
     * Return the instant in UTC, to the microsecond.
     *
     * @param  \Carbon\CarbonImmutable  $instant
     * @return string
     */
    private static function instant(CarbonImmutable $instant): string
    {
        return $instant->utc()->format(self::INSTANT);
    }
}
