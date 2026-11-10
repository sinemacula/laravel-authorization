<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authorization\Reviews\Enums\GrantState;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\SupportingGrant;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The rows one run of an access review collects, each built from the stored row
 * its route starts from and the rows it rests on, with its key in the review's
 * order (see `ReviewOrder`): its kind, its target, the starting row's grantee
 * and scope, then its route.
 *
 * The run asks for one more row than its limit, so whether a row was left out
 * is known exactly: the review is truncated only when more rows were collected
 * than the limit, and only the limit's worth is returned.
 *
 * A review of unused grants keeps only the rows its filter keeps (see
 * `ReviewUsage::isUnobserved()`); a row it leaves out is not collected, so the
 * limit and the truncation count the rows kept.
 *
 * A later page collects only the rows after the last row of the page before, by
 * its sort key (`after`): a row at or before it is passed over, a source of
 * rows whose kind comes before the last row's is not read at all (see
 * `isPast()`), and the source of the last row's kind resumes from its stored
 * row (see `resumeAt()`). A sort key holds, in this order, the kind's position
 * (index 0), the target's type and key (1 and 2, `TARGET`), the stored row's
 * grantee and scope as `GrantRow::orderKey()` gives them (3 to 11, `STORED`),
 * then the route (12 on, `ROUTE`, see `routeKey()`): the first role of its
 * chain and how many roles the chain runs through, then the keys of the rows it
 * rests on. A chain runs from one role up through its parents, so its first
 * role and its length name it among the routes of one stored row, and a sort
 * key, and the cursor that carries one (see `ReviewCursor`), stays the same
 * size however deep the hierarchy runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RowCollector
{
    /** @var int The index in a sort key of the target's key. */
    public const int TARGET = 2;

    /** @var int The index in a sort key where the stored row's grantee and scope begin. */
    public const int STORED = 3;

    /** @var int The index in a sort key where the route begins. */
    public const int ROUTE = 12;

    /** @var list<array{key: list<bool|int|string|null>, row: \SineMacula\Laravel\Authorization\Reviews\ReviewRow}> The rows collected, each with its sort key, in the order collected. */
    private array $entries = [];

    /**
     * Create an empty collection of rows.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  int  $limit
     * @param  list<bool|int|string|null>|null  $after
     * @param  (\Closure(\SineMacula\Laravel\Authorization\Reviews\ReviewRow): bool)|null  $keeps
     */
    public function __construct(

        /** The run the rows are collected for. */
        private readonly ReviewRun $run,

        /** The most rows the review returns. */
        private readonly int $limit,

        /** The sort key of the last row of the page before; null for the first page. */
        private readonly ?array $after = null,

        /** Whether a row is kept, as an unused review keeps only the rows with no observed use; null keeps every row. */
        private readonly ?\Closure $keeps = null,
    ) {}

    /**
     * Determine whether every row of the kind comes before the last row of the
     * page before, so a source of them need not be read.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $kind
     * @return bool
     */
    public function isPast(SourceKind $kind): bool
    {
        return $this->after !== null && $kind->position() < $this->after[0];
    }

    /**
     * Return the sort key of the last row of the page before when it is of the
     * kind, so a source of the kind resumes from its stored row; null when the
     * source is read from its start.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $kind
     * @return list<bool|int|string|null>|null
     */
    public function resumeAt(SourceKind $kind): ?array
    {
        return $this->after !== null && $this->after[0] === $kind->position() ? $this->after : null;
    }

    /**
     * Return how many rows the run still needs to know whether any is left out:
     * one more than the limit, less those collected, at least none.
     *
     * @return int
     */
    public function room(): int
    {
        return \max(0, $this->limit + 1 - \count($this->entries));
    }

    /**
     * Determine whether enough rows are collected to know one is left out.
     *
     * @return bool
     */
    public function isFull(): bool
    {
        return $this->room() === 0;
    }

    /**
     * Collect the row of a route: of the kind, by which the subject holds the
     * target, starting from the stored row, through the roles of the chain,
     * resting on the further rows, through the identity when one is given;
     * passed over when it is at or before the last row of the page before.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $subject
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow  $start
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $target
     * @param  list<string>  $chain
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>  $rests
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $via
     * @return void
     */
    public function route(SourceKind $kind, Reference $subject, GrantRow $start, Reference $target, array $chain = [], array $rests = [], ?Reference $via = null): void
    {
        $key = [$kind->position(), $target->type, $target->id, ...$start->orderKey(), ...self::routeKey($chain, $rests)];

        if ($this->after !== null && ReviewOrder::compare($key, $this->after) <= 0) {
            return;
        }

        $rows       = [$start, ...$rests];
        $supporting = \array_map(static fn (GrantRow $row): SupportingGrant => $row->supporting(), $rows);
        $keys       = \array_map(static fn (GrantRow $row): string => $row->key(), $rows);
        $expiries   = \array_filter(\array_map(static fn (GrantRow $row): ?CarbonImmutable => $row->expiresAt(), $rows));

        $times = [...$start->times, 'route_expires_at' => $expiries === [] ? null : \min($expiries)];

        $row = new ReviewRow(
            \hash('sha256', ReviewOrder::key([$kind->value, $subject->type, $subject->id, $target->type, $target->id, ...$keys, ...$chain])),
            $subject,
            $start->grantee,
            $target,
            $kind,
            $start->key(),
            $start->originScope(),
            $via,
            RoleChains::path($chain),
            $supporting,
            $times,
            $start->grantedBy,
            $this->stateOf($start, $rows),
        );

        if ($this->keeps !== null && !($this->keeps)($row)) {
            return;
        }

        $this->entries[] = ['key' => $key, 'row' => $row];
    }

    /**
     * Return the part of a sort key that orders a route among the routes of one
     * stored row: the first role of its chain and how many roles the chain runs
     * through, none for no chain, then the key of each row it rests on.
     *
     * @param  list<string>  $chain
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>  $rests
     * @return list<int|string>
     */
    public static function routeKey(array $chain, array $rests): array
    {
        $roles = $chain === [] ? [] : [$chain[0], \count($chain)];

        return [...$roles, ...\array_map(static fn (GrantRow $row): string => $row->key(), $rests)];
    }

    /**
     * Return the rows to return, at most the limit of them, in the order
     * collected, or sorted into the review's order when asked, which the rows
     * collected then keep (see `next()`).
     *
     * @param  bool  $isSorted
     * @return list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>
     */
    public function rows(bool $isSorted = false): array
    {
        if ($isSorted) {
            \usort($this->entries, static fn (array $one, array $other): int => ReviewOrder::compare($one['key'], $other['key']));
        }

        return \array_map(static fn (array $entry): ReviewRow => $entry['row'], \array_slice($this->entries, 0, $this->limit));
    }

    /**
     * Return the sort key of the last row returned when a row was left out, so
     * the next page starts after it; null when none was, as this is the last
     * page. The rows are read in the order `rows()` last left them.
     *
     * @return list<bool|int|string|null>|null
     */
    public function next(): ?array
    {
        return $this->isTruncated() ? $this->entries[$this->limit - 1]['key'] : null;
    }

    /**
     * Determine whether a row was left out: more were collected than the limit.
     *
     * @return bool
     */
    public function isTruncated(): bool
    {
        return \count($this->entries) > $this->limit;
    }

    /**
     * Return the state of a route: malformed when a row it rests on names half
     * a tenant, else live while the row it starts from still counts at the
     * run's instant, and expired once it does not.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow  $start
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>  $rows
     * @return \SineMacula\Laravel\Authorization\Reviews\Enums\GrantState
     */
    private function stateOf(GrantRow $start, array $rows): GrantState
    {
        return match (true) {
            \array_filter($rows, static fn (GrantRow $row): bool => $row->isMalformed()) !== [] => GrantState::MALFORMED,
            $start->isLiveAt($this->run->now)                                                   => GrantState::LIVE,
            default                                                                             => GrantState::EXPIRED,
        };
    }
}
