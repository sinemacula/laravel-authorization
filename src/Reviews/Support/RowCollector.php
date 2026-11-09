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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RowCollector
{
    /** @var list<array{key: list<bool|int|string|null>, row: \SineMacula\Laravel\Authorization\Reviews\ReviewRow}> The rows collected, each with its sort key, in the order collected. */
    private array $entries = [];

    /**
     * Create an empty collection of rows.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  int  $limit
     */
    public function __construct(

        /** The run the rows are collected for. */
        private readonly ReviewRun $run,

        /** The most rows the review returns. */
        private readonly int $limit,
    ) {}

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
     * resting on the further rows, through the identity when one is given.
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
        $rows       = [$start, ...$rests];
        $supporting = \array_map(static fn (GrantRow $row): SupportingGrant => $row->supporting(), $rows);
        $keys       = \array_map(static fn (GrantRow $row): string => $row->key(), $rows);
        $expiries   = \array_filter(\array_map(static fn (GrantRow $row): ?CarbonImmutable => $row->expiresAt(), $rows));
        $route      = [...$chain, ...\array_map(static fn (GrantRow $row): string => $row->key(), $rests)];

        $times = [...$start->times, 'route_expires_at' => $expiries === [] ? null : \min($expiries)];

        $row = new ReviewRow(
            \hash('sha256', ReviewOrder::key([$kind->value, $subject->type, $subject->id, $target->type, $target->id, ...$keys, ...$chain])),
            $subject,
            $start->grantee,
            $target,
            $kind,
            $start->key(),
            $start->scope,
            $via,
            RoleChains::path($chain),
            $supporting,
            $times,
            $start->grantedBy,
            $start->isLiveAt($this->run->now) ? GrantState::LIVE : GrantState::EXPIRED,
        );

        $this->entries[] = ['key' => [$kind->position(), $target->type, $target->id, ...$start->orderKey(), ...$route], 'row' => $row];
    }

    /**
     * Return the rows to return, at most the limit of them, in the order
     * collected, or sorted into the review's order when asked.
     *
     * @param  bool  $isSorted
     * @return list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>
     */
    public function rows(bool $isSorted = false): array
    {
        $entries = $this->entries;

        if ($isSorted) {
            \usort($entries, static fn (array $one, array $other): int => ReviewOrder::compare($one['key'], $other['key']));
        }

        return \array_map(static fn (array $entry): ReviewRow => $entry['row'], \array_slice($entries, 0, $this->limit));
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
}
