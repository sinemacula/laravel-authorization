<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;

/**
 * The package's grant usage store (N102), on its own tables on the package's
 * connection: `authorization.tables.grant_usage`, one row for each grant route
 * with its last observed bucket and the creation of the grant it was observed
 * through, and `authorization.tables.usage_coverage`, the periods tracking was
 * on.
 *
 * Writes are monotonic and idempotent, so a batch delivered twice, or after a
 * later one, changes nothing: a route's row is written only when the
 * observation is newer than what it keeps, the grant's creation first, then the
 * bucket, each compared in the update itself, so two workers writing the same
 * route at once keep the newer. The routes are written in the order of their
 * keys, a hundred to a transaction, the rows missing inserted before any is
 * rewritten and no row read under a lock, so two workers writing the same
 * routes take their locks in the same order. A transaction that deadlocks or
 * waits too long for a lock is tried again, three times in all; one that still
 * fails throws, and the coverage is not extended.
 *
 * Coverage is extended under a row lock on the latest period: a batch at or
 * before that period's end leaves it as it is; one within two intervals of it
 * extends it; any later one opens a new period at the batch's instant. A batch
 * that names observations dropped before it first cuts every period back to two
 * intervals and a second before the earliest bucket dropped, so with the two
 * intervals a review allows past a period's end the time lost stays uncovered
 * and its routes read `unknown`; the batch then opens a new period. Every read
 * is on the write connection.
 *
 * @phpstan-import-type Observation from \SineMacula\Laravel\Authorization\Usage\UsageBatch
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DatabaseGrantUsageStore implements GrantUsageStore
{
    /** @var int How many routes one statement reads, or one transaction writes, at most. */
    private const int CHUNK = 100;

    /** @var int How many times a transaction is tried, in all, when it deadlocks or waits too long for a lock. */
    private const int ATTEMPTS = 3;

    /** @var string The format every instant is stored in, in UTC. */
    private const string FORMAT = 'Y-m-d H:i:s';

    /**
     * Keep the batch's observations, each only when it is newer than what is
     * kept for its route, then extend the coverage to the batch's instant.
     *
     * @param  \SineMacula\Laravel\Authorization\Usage\UsageBatch  $batch
     * @return void
     *
     * @throws \Throwable
     */
    #[\Override]
    public function record(UsageBatch $batch): void
    {
        foreach (\array_chunk(self::newestOf($batch->observations()), self::CHUNK) as $chunk) {
            self::upsert($chunk);
        }

        self::extend($batch->at, $batch->lostSince);
    }

    /**
     * Return what is kept of each of the route keys that has any, by its key.
     *
     * @param  list<string>  $keys
     * @return array<string, \SineMacula\Laravel\Authorization\Usage\ObservedUse>
     */
    #[\Override]
    public function lastObserved(array $keys): array
    {
        $found = [];

        foreach (\array_chunk($keys, self::CHUNK) as $chunk) {
            foreach (self::usage()->whereIn('grant_key', $chunk)->get(['grant_key', 'grant_created_at', 'last_observed_at']) as $row) {
                [$key, $created, $observed] = self::keptIn($row);

                $found[$key] = new ObservedUse($observed, $created);
            }
        }

        return $found;
    }

    /**
     * Return the periods tracking was on that overlap the UTC half-open window
     * `[from, until)`, in the order they began.
     *
     * @param  \Carbon\CarbonImmutable  $from
     * @param  \Carbon\CarbonImmutable  $until
     * @return list<\SineMacula\Laravel\Authorization\Usage\CoveragePeriod>
     */
    #[\Override]
    public function coverage(CarbonImmutable $from, CarbonImmutable $until): array
    {
        $periods = [];
        $rows    = self::periods()
            ->where('covered_from', '<', $until->utc()->format(self::FORMAT))
            ->where('covered_until', '>=', $from->utc()->format(self::FORMAT))
            ->orderBy('covered_from')
            ->orderBy('id')
            ->get(['covered_from', 'covered_until']);

        foreach ($rows as $row) {
            $columns = (array) $row;

            $periods[] = new CoveragePeriod(self::required($columns['covered_from'] ?? null), self::required($columns['covered_until'] ?? null));
        }

        return $periods;
    }

    /**
     * Return the newest observation of each route among the observations, as
     * the store compares them: the grant's creation first, then the bucket, in
     * the order of their keys.
     *
     * @param  list<Observation>  $observations
     * @return array<string, Observation>
     */
    private static function newestOf(array $observations): array
    {
        $newest = [];

        foreach ($observations as $observation) {
            $kept = $newest[$observation['grant_key']] ?? null;

            if ($kept !== null && !self::isNewer($observation, $kept['grant_created_at'], $kept['last_observed_at'])) {
                continue;
            }

            $newest[$observation['grant_key']] = $observation;
        }

        \ksort($newest, \SORT_STRING);

        return $newest;
    }

    /**
     * Write each observation of the chunk whose route has no row, then rewrite
     * the row of each whose observation is newer than what it keeps, in one
     * transaction, tried again when it deadlocks or waits too long for a lock.
     * What the rows keep is read first without a lock, so a route a concurrent
     * writer inserted first is rewritten too, when the observation is newer
     * than what it wrote, and the update itself compares them.
     *
     * @param  list<Observation>  $chunk
     * @return void
     *
     * @throws \Throwable
     */
    private static function upsert(array $chunk): void
    {
        AuthorizationConnection::connection()->transaction(static function () use ($chunk): void {
            $kept    = self::keptOf(\array_column($chunk, 'grant_key'));
            $missing = \array_filter($chunk, static fn (array $observation): bool => !isset($kept[$observation['grant_key']]));
            $newer   = \array_filter(
                $chunk,
                static fn (array $observation): bool => isset($kept[$observation['grant_key']]) && self::isNewer($observation, ...$kept[$observation['grant_key']]),
            );
            $isRaced = $missing !== [] && self::usage()->insertOrIgnore(\array_map(self::row(...), $missing)) !== \count($missing);

            foreach ($isRaced ? $chunk : $newer as $observation) {
                self::rewrite($observation);
            }
        }, self::ATTEMPTS);
    }

    /**
     * Return what the rows of the routes with the keys keep, each as the
     * grant's creation and the bucket, by the route's key.
     *
     * @param  list<string>  $keys
     * @return array<string, array{int|null, int}>
     */
    private static function keptOf(array $keys): array
    {
        $kept = [];

        foreach (self::usage()->whereIn('grant_key', $keys)->get(['grant_key', 'grant_created_at', 'last_observed_at']) as $row) {
            [$key, $created, $observed] = self::keptIn($row);

            $kept[$key] = [$created?->getTimestamp(), $observed->getTimestamp()];
        }

        return $kept;
    }

    /**
     * Return the route's key, the grant's creation and the bucket a usage row
     * keeps.
     *
     * @param  object  $row
     * @return array{string, \Carbon\CarbonImmutable|null, \Carbon\CarbonImmutable}
     */
    private static function keptIn(object $row): array
    {
        $columns = (array) $row;
        $key     = $columns['grant_key'] ?? null;

        return [\is_scalar($key) ? (string) $key : '', self::instant($columns['grant_created_at'] ?? null), self::required($columns['last_observed_at'] ?? null)];
    }

    /**
     * Determine whether the observation is newer than what is kept: of a grant
     * created later, or of the same grant in a later bucket. A grant that
     * records no creation counts as created before any that does.
     *
     * @param  Observation  $observation
     * @param  int|null  $createdAt
     * @param  int  $observedAt
     * @return bool
     */
    private static function isNewer(array $observation, ?int $createdAt, int $observedAt): bool
    {
        $created = $observation['grant_created_at'] ?? \PHP_INT_MIN;
        $kept    = $createdAt                       ?? \PHP_INT_MIN;

        return $created > $kept || ($created === $kept && $observation['last_observed_at'] > $observedAt);
    }

    /**
     * Rewrite the route's row with the observation, only where what it keeps is
     * older, compared in the update itself, so a concurrent writer's newer
     * observation is never overwritten.
     *
     * @param  Observation  $observation
     * @return void
     */
    private static function rewrite(array $observation): void
    {
        $created  = self::stored($observation['grant_created_at']);
        $observed = self::stored($observation['last_observed_at']);

        self::usage()
            ->where('grant_key', $observation['grant_key'])
            ->where(static function (Builder $older) use ($created, $observed): void {
                if ($created === null) {
                    $older->whereNull('grant_created_at')->where('last_observed_at', '<', $observed);

                    return;
                }

                $older->whereNull('grant_created_at')
                    ->orWhere('grant_created_at', '<', $created)
                    ->orWhere(static function (Builder $same) use ($created, $observed): void {
                        $same->where('grant_created_at', '=', $created)->where('last_observed_at', '<', $observed);
                    });
            })
            ->update(\array_diff_key(self::row($observation), ['grant_key' => true]));
    }

    /**
     * Extend the coverage to the instant, under a row lock on the latest
     * period, in a transaction tried again when it deadlocks or waits too long
     * for a lock: first, when observations were dropped since the bucket
     * starting at `lostSince`, cut the coverage back before it; then leave the
     * latest period when it already reaches the instant, extend it when it
     * ended within two intervals of it, or open a new period at the instant.
     *
     * @param  int  $at
     * @param  int|null  $lostSince
     * @return void
     *
     * @throws \Throwable
     */
    private static function extend(int $at, ?int $lostSince): void
    {
        $gap = 2 * UsageTracking::interval();

        AuthorizationConnection::connection()->transaction(static function () use ($at, $lostSince, $gap): void {
            if ($lostSince !== null) {
                self::cut($lostSince - $gap - 1, $at);
            }

            $last  = self::periods()->orderByDesc('covered_until')->orderByDesc('id')->lockForUpdate()->first(['id', 'covered_until']);
            $until = $last === null ? null : self::required(((array) $last)['covered_until'] ?? null)->getTimestamp();

            match (true) {
                $until === null || $at - $until > $gap => self::periods()->insert(['covered_from' => self::stored($at), 'covered_until' => self::stored($at)]),
                $until < $at                           => self::periods()->where('id', ((array) $last)['id'] ?? null)->update(['covered_until' => self::stored($at)]),
                default                                => null,
            };
        }, self::ATTEMPTS);
    }

    /**
     * Remove the coverage between the instants: a period that starts before the
     * cut is ended there, one that ends after the instant then starts there,
     * and one wholly between them is removed.
     *
     * @param  int  $cut
     * @param  int  $at
     * @return void
     */
    private static function cut(int $cut, int $at): void
    {
        $overlapping = self::periods()
            ->where('covered_until', '>', self::stored($cut))
            ->where('covered_from', '<', self::stored($at))
            ->lockForUpdate()
            ->get(['id', 'covered_from', 'covered_until']);

        foreach ($overlapping as $period) {
            $columns = (array) $period;
            $from    = self::required($columns['covered_from'] ?? null)->getTimestamp();
            $until   = self::required($columns['covered_until'] ?? null)->getTimestamp();
            $row     = self::periods()->where('id', $columns['id'] ?? null);

            if ($from < $cut && $until > $at) {
                self::periods()->insert(['covered_from' => self::stored($at), 'covered_until' => self::stored($until)]);
            }

            match (true) {
                $from < $cut => $row->update(['covered_until' => self::stored($cut)]),
                $until > $at => $row->update(['covered_from' => self::stored($at)]),
                default      => $row->delete(),
            };
        }
    }

    /**
     * Return the row the observation is kept as.
     *
     * @param  Observation  $observation
     * @return array<string, string|null>
     */
    private static function row(array $observation): array
    {
        return [
            'grant_key'         => $observation['grant_key'],
            'grant_source'      => $observation['grant_source'],
            'grant_id'          => $observation['grant_id'],
            'authorizable_type' => $observation['authorizable_type'],
            'authorizable_id'   => $observation['authorizable_id'],
            'tenant_type'       => $observation['tenant_type'],
            'tenant_id'         => $observation['tenant_id'],
            'application'       => $observation['application'],
            'grant_created_at'  => self::stored($observation['grant_created_at']),
            'last_observed_at'  => self::stored($observation['last_observed_at']),
        ];
    }

    /**
     * Return the timestamp as the UTC wall-clock time the tables store, or null
     * for none.
     *
     * @param  int|null  $timestamp
     * @return ($timestamp is null ? null : string)
     */
    private static function stored(?int $timestamp): ?string
    {
        return $timestamp === null ? null : CarbonImmutable::createFromTimestampUTC($timestamp)->format(self::FORMAT);
    }

    /**
     * Return the stored UTC wall-clock time as an instant, or null for none.
     *
     * @param  mixed  $value
     * @return \Carbon\CarbonImmutable|null
     */
    private static function instant(mixed $value): ?CarbonImmutable
    {
        $instant = UtcDateTime::toUtc($value);

        return $instant === null ? null : CarbonImmutable::instance($instant);
    }

    /**
     * Return the stored UTC wall-clock time of a column that is never null as
     * an instant.
     *
     * @param  mixed  $value
     * @return \Carbon\CarbonImmutable
     *
     * @throws \UnexpectedValueException
     */
    private static function required(mixed $value): CarbonImmutable
    {
        return self::instant($value) ?? throw new \UnexpectedValueException('A grant usage table holds no time where one is required.');
    }

    /**
     * Query the usage table on the write connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function usage(): Builder
    {
        /** @var string $table */
        $table = config('authorization.tables.grant_usage', 'grant_usage');

        return AuthorizationConnection::connection()->table($table)->useWritePdo();
    }

    /**
     * Query the coverage table on the write connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function periods(): Builder
    {
        /** @var string $table */
        $table = config('authorization.tables.usage_coverage', 'usage_coverage');

        return AuthorizationConnection::connection()->table($table)->useWritePdo();
    }
}
