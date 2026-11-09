<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind;
use SineMacula\Laravel\Authorization\Reviews\Support\HolderRoutes;
use SineMacula\Laravel\Authorization\Reviews\Support\HoldingRoutes;
use SineMacula\Laravel\Authorization\Reviews\Support\JsonLinesExport;
use SineMacula\Laravel\Authorization\Reviews\Support\PageRead;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewCursor;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewPosition;
use SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun;
use SineMacula\Laravel\Authorization\Reviews\Support\RowCollector;
use SineMacula\Laravel\Authorization\Reviews\Support\StoredRows;
use SineMacula\Laravel\Authorization\Reviews\Support\SubjectStates;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;

/**
 * Runs access reviews (AUTHZ-11.6, N93 to N98): who holds a role, permission or
 * policy, what a subject holds, what expires, and what an actor last granted,
 * for periodic reviews and their sign-off.
 *
 * A review lists grant routes, never effective access: one row for each route
 * by which a subject holds a target through the stored grants, every row it
 * rests on live at the review's instant. It reads structure alone, the same
 * tenant chain, application matching, live-grant and definition-visibility
 * rules a check reads, and never evaluates a statement, condition, deny or cap
 * (D22), so a policy that only denies is held, and a holder may be denied what
 * it holds; `check()`, `permissionsFor()` and a preview say what a subject may
 * do. Boundaries, guardrails and resource-policy attachments restrict or extend
 * what is decided, but are not held, so no review lists them.
 *
 * `review()` runs a review as the reviewer, admitted first (see
 * `ReviewAdmission`): a refused review throws `AuthorizationException` before
 * anything is read, so it discloses no row, count, truncation or completeness.
 * It returns the review's first page, at most its limit of rows, saying whether
 * more were left out. `trusted()` runs one as trusted system work (N75), for a
 * scheduled job or a command, with no reviewer and no admission; nothing else
 * falls back to it, and an acting context that cannot be resolved is refused
 * before a review is reached. Each entry point has its trusted counterpart:
 * `trustedPage()`, `trustedStream()` and `trustedExport()`.
 *
 * `page()` reads a review a page at a time by keyset over the review's one
 * total order, never by offset, so a page costs the same queries whatever its
 * number: the first page with no cursor, then each with the opaque, signed
 * cursor the page before returned (see `Support\ReviewCursor`), which binds the
 * query, the reviewer or the trusted path, the row schema version and the
 * review's instant, frozen when the first page is read so every page classifies
 * each expiry alike. Every page is admitted again before anything, its cursor
 * included, is read, so a right revoked between pages refuses the next. The
 * scan is live, not a database snapshot: a row written or revoked between pages
 * may appear or disappear, but a row present throughout the scan is returned
 * exactly once.
 *
 * `stream()` returns every row lazily, read through the same pages a chunk at a
 * time and admitted again before each chunk, so what is held in memory is
 * bounded by the chunk, however large the tenant (one subject's holdings are
 * read whole, by design). `export()` writes the rows as versioned JSON Lines, a
 * header, one line a row and a footer (see `Support\JsonLinesExport`), to a
 * stream resource or a callback, and needs both `authorization:review.read` and
 * `authorization:review.export` (N96, N97), decided together before the header
 * and again before every chunk; an export refused or failing part way stops
 * with no footer.
 *
 * Every read is on the write connection, as every other grant read is, never
 * one query per holder: the grants are read a page of the limit at a time, and
 * whether a role's grant meets a policy attached to the role is settled in a
 * fixed number of queries, never one for each tenant a grant is held in (one
 * subject's holdings are read whole, an identity's principals a chunk at a
 * time, then ordered). The rows come in one deterministic order, the same on
 * every supported database (see `Support\ReviewOrder`), and a review, a page, a
 * stream and an export share one read: one query construction, admission and
 * projection (D22).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AccessReview
{
    /** @var int The rows a stream or an export reads a chunk at a time by default. */
    public const int CHUNK = 1000;

    /**
     * Create a new access review service.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the identity directory is read from on every review of an identity's holdings. */
        private Container $container,
    ) {}

    /**
     * Run the review as the reviewer, once the reviewer is admitted to it: its
     * first page, at most its limit of rows, saying whether more were left out.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $reviewer
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewResult
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function review(ReviewQuery $query, ActingContext $reviewer): ReviewResult
    {
        ReviewAdmission::admit($reviewer, ReviewResource::of($query));

        return self::resultOf($this->read($query, ReviewPosition::start()));
    }

    /**
     * Run the review as trusted system work, with no reviewer and no admission.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewResult
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function trusted(ReviewQuery $query): ReviewResult
    {
        return self::resultOf($this->read($query, ReviewPosition::start()));
    }

    /**
     * Read a page of the review as the reviewer, admitted again for every page
     * before anything, the cursor included, is read: the first page with no
     * cursor, else the page after the one the cursor was issued with, at most
     * the limit of rows, the query's own when none is given.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $reviewer
     * @param  string|null  $cursor
     * @param  int|null  $limit
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewPage
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidReviewCursorException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function page(ReviewQuery $query, ActingContext $reviewer, ?string $cursor = null, ?int $limit = null): ReviewPage
    {
        ReviewAdmission::admit($reviewer, ReviewResource::of($query));

        return $this->pageOf($query, $reviewer, $cursor, $limit);
    }

    /**
     * Read a page of the review as trusted system work, with no reviewer and no
     * admission; its cursors serve the trusted path alone.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  string|null  $cursor
     * @param  int|null  $limit
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewPage
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidReviewCursorException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function trustedPage(ReviewQuery $query, ?string $cursor = null, ?int $limit = null): ReviewPage
    {
        return $this->pageOf($query, null, $cursor, $limit);
    }

    /**
     * Return every row of the review as the reviewer, lazily: nothing is read
     * until the rows are iterated, then each chunk of rows is read, after the
     * reviewer is admitted again, only once the rows before it are taken; a
     * refusal at any chunk throws `AuthorizationException` from the iteration.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $reviewer
     * @param  int  $chunk
     * @return iterable<int, \SineMacula\Laravel\Authorization\Reviews\ReviewRow>
     *
     * @throws \InvalidArgumentException
     */
    public function stream(ReviewQuery $query, ActingContext $reviewer, int $chunk = self::CHUNK): iterable
    {
        return self::rowsOf($this->pages($query->withLimit($chunk), self::admission($reviewer, $query)));
    }

    /**
     * Return every row of the review as trusted system work, lazily, a chunk at
     * a time.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  int  $chunk
     * @return iterable<int, \SineMacula\Laravel\Authorization\Reviews\ReviewRow>
     *
     * @throws \InvalidArgumentException
     */
    public function trustedStream(ReviewQuery $query, int $chunk = self::CHUNK): iterable
    {
        return self::rowsOf($this->pages($query->withLimit($chunk), null));
    }

    /**
     * Export the review as the reviewer, as JSON Lines (see
     * `Support\JsonLinesExport`), to a writable stream resource or a callback
     * given each line, a chunk of rows at a time: the reviewer is admitted to
     * read and to export the review, both together, before the header is
     * written and again before every chunk; return how many rows were written.
     * A refusal at any chunk throws `AuthorizationException`, and a stream that
     * takes none of a line `ReviewExportException`, so an export that stops
     * part way has no footer.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $reviewer
     * @param  (callable(string): mixed)|resource  $sink
     * @param  int  $chunk
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function export(ReviewQuery $query, ActingContext $reviewer, mixed $sink, int $chunk = self::CHUNK): int
    {
        return $this->exportTo($query, $sink, $chunk, self::admission($reviewer, $query, PackagePermissions::REVIEW_READ, PackagePermissions::REVIEW_EXPORT));
    }

    /**
     * Export the review as trusted system work, with no reviewer and no
     * admission, as JSON Lines.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  (callable(string): mixed)|resource  $sink
     * @param  int  $chunk
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    public function trustedExport(ReviewQuery $query, mixed $sink, int $chunk = self::CHUNK): int
    {
        return $this->exportTo($query, $sink, $chunk, null);
    }

    /**
     * Read the page the cursor names, or the first, for the reviewer, or the
     * trusted path for none, and return it with the cursor of the page after
     * it, if any.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|null  $reviewer
     * @param  string|null  $cursor
     * @param  int|null  $limit
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewPage
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidReviewCursorException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function pageOf(ReviewQuery $query, ?ActingContext $reviewer, ?string $cursor, ?int $limit): ReviewPage
    {
        $sized    = $limit  === null ? $query : $query->withLimit($limit);
        $position = $cursor === null ? ReviewPosition::start() : ReviewCursor::forApplication()->read($cursor, $query, $reviewer);
        $read     = $this->read($sized, $position);
        $next     = $read->next === null ? null : ReviewCursor::forApplication()->issue($read->next, $query, $reviewer);

        return new ReviewPage($read->rows, $next, $read->at, $read->isComplete);
    }

    /**
     * Write the export of the review to the sink, its pages read a chunk at a
     * time, each admitted first when an admission is given.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  mixed  $sink
     * @param  int  $chunk
     * @param  (\Closure(): void)|null  $admit
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \JsonException
     */
    private function exportTo(ReviewQuery $query, mixed $sink, int $chunk, ?\Closure $admit): int
    {
        $sized  = $query->withLimit($chunk);
        $export = JsonLinesExport::into($sink);

        return $export->write($query, $this->pages($sized, $admit), CarbonImmutable::now('UTC'));
    }

    /**
     * Return the pages of the review, lazily, from the first to the last, each
     * read only once the one before is taken, after the admission, when one is
     * given, is decided again.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  (\Closure(): void)|null  $admit
     * @return \Generator<int, \SineMacula\Laravel\Authorization\Reviews\Support\PageRead>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private function pages(ReviewQuery $query, ?\Closure $admit): \Generator
    {
        $position = ReviewPosition::start();

        while ($position !== null) {
            if ($admit !== null) {
                $admit();
            }

            $page     = $this->read($query, $position);
            $position = $page->next;

            yield $page;
        }
    }

    /**
     * Read one page of the review from the position: the one read every review,
     * page, stream and export shares (D22). Its rows are collected in the
     * review's order after the position's last row, at most the limit of them
     * and at least one more to know whether any is left, with what is known of
     * their subjects, at the position's frozen instant.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewPosition  $position
     * @return \SineMacula\Laravel\Authorization\Reviews\Support\PageRead
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private function read(ReviewQuery $query, ReviewPosition $position): PageRead
    {
        $run  = ReviewRun::of($query->scope, $position->at);
        $rows = new RowCollector($run, $query->limit, $position->after);

        $isComplete = match ($query->kind) {
            ReviewKind::HOLDERS  => HolderRoutes::read($run, $query, $rows),
            ReviewKind::HOLDINGS => HoldingRoutes::read($run, $query, $rows, $this->directory()),
            ReviewKind::EXPIRING,
            ReviewKind::GRANTED_BY => StoredRows::read($run, $query, $rows),
        };

        $read = $rows->rows($query->kind === ReviewKind::HOLDINGS);
        $next = $rows->next();

        return new PageRead(SubjectStates::apply($read, $query->subject), $next === null ? null : $position->after($next), $isComplete, $run->now);
    }

    /**
     * Return the admission of the reviewer to the review, deciding the rights
     * named, the read right when none is, each time it is called.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $reviewer
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  string  ...$actions
     * @return \Closure(): void
     */
    private static function admission(ActingContext $reviewer, ReviewQuery $query, string ...$actions): \Closure
    {
        $resource = ReviewResource::of($query);

        return static function () use ($reviewer, $resource, $actions): void {
            ReviewAdmission::admit($reviewer, $resource, ...$actions);
        };
    }

    /**
     * Return the rows of the pages, lazily, in their order.
     *
     * @param  iterable<\SineMacula\Laravel\Authorization\Reviews\Support\PageRead>  $pages
     * @return \Generator<int, \SineMacula\Laravel\Authorization\Reviews\ReviewRow>
     */
    private static function rowsOf(iterable $pages): \Generator
    {
        foreach ($pages as $page) {
            foreach ($page->rows as $row) {
                yield $row;
            }
        }
    }

    /**
     * Return the first page of a review as a bounded result, truncated when
     * another page follows it.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\PageRead  $page
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewResult
     */
    private static function resultOf(PageRead $page): ReviewResult
    {
        return new ReviewResult($page->rows, $page->next !== null, $page->isComplete, $page->at);
    }

    /**
     * Return the bound identity directory.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory
     */
    private function directory(): IdentityDirectory
    {
        /** @var \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory */
        return $this->container->make(IdentityDirectory::class);
    }
}
