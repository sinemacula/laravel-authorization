<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Reviews\Enums\UsageStatus;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewRow;
use SineMacula\Laravel\Authorization\Reviews\RowUsage;
use SineMacula\Laravel\Authorization\Usage\GrantUsageKey;
use SineMacula\Laravel\Authorization\Usage\ObservedUse;
use SineMacula\Laravel\Authorization\Usage\UsageTracking;

/**
 * What one read of an access review knows of its rows' use (N94): each row's
 * `usage` (see `RowUsage`), read from the bound usage store in one batched
 * lookup of the page's routes and one read of the coverage, never one for each
 * row.
 *
 * A row's window runs from the later of the review's `since` (an unused
 * review's) and its grant's creation to the review's instant. The route was
 * `used` when it was observed, through the grant as it stands now, in a bucket
 * that ends after the window starts; else `unused` when the periods tracking
 * was on cover the whole window, each taken to reach two intervals past its
 * end, the most a flush or heartbeat may lag while tracking runs; else
 * `unknown`. An observation through a grant created before the current one (a
 * revoked grant made again) is ignored.
 *
 * Every row is `unknown`, and nothing is read, while tracking is off. So is a
 * row whose source cannot report its use: a role's permission edge or policy
 * attachment, which no check uses on its own, and a grant to a grantee whose
 * grants the package does not resolve (a `getPermissions()` or `getPolicies()`
 * of its own) or, for a policy, while a policy resolver of the application's is
 * bound; a role's grant needs both its permissions and its policies to be
 * reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReviewUsage
{
    /** @var array<string, false|\SineMacula\Laravel\Authorization\Usage\ObservedUse> What the store keeps of each route looked up, false for none. */
    private array $observed = [];

    /** @var list<\SineMacula\Laravel\Authorization\Usage\CoveragePeriod> The periods tracking was on that were read. */
    private array $periods = [];

    /** @var \Carbon\CarbonImmutable|null The earliest window start the periods were read from; null until they are. */
    private ?CarbonImmutable $coveredFrom = null;

    /** @var array<string, bool> Whether each grantee type can report the use of each kind of grant, by the type and the kind. */
    private array $reporting = [];

    /**
     * Create what a read knows of its rows' use.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\GrantUsageStore|null  $store
     * @param  int  $interval
     * @param  \Carbon\CarbonImmutable|null  $since
     * @param  \Carbon\CarbonImmutable  $at
     */
    public function __construct(

        /** The store usage is read from; null while tracking is off. */
        private readonly ?GrantUsageStore $store,

        /** The length of a bucket, in seconds. */
        private readonly int $interval,

        /** The instant an unused review looks back to; null for any other review. */
        private readonly ?CarbonImmutable $since,

        /** The review's instant, where every window ends. */
        private readonly CarbonImmutable $at,
    ) {}

    /**
     * Return what a read of the query at the instant knows of its rows' use,
     * reading the bound store only while tracking is on.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewQuery  $query
     * @param  \Carbon\CarbonImmutable  $at
     * @return self
     */
    public static function forQuery(ReviewQuery $query, CarbonImmutable $at): self
    {
        if (!UsageTracking::isEnabled()) {
            return new self(null, UsageTracking::INTERVAL, $query->since(), $at);
        }

        /** @var \SineMacula\Laravel\Authorization\Contracts\GrantUsageStore $store */
        $store = Container::getInstance()->make(GrantUsageStore::class);

        return new self($store, UsageTracking::interval(), $query->since(), $at);
    }

    /**
     * Read what the store keeps of the routes not read yet, in one lookup, and
     * the coverage from the earliest window start given, unless it was read
     * from as early already.
     *
     * @param  list<string>  $keys
     * @param  \Carbon\CarbonImmutable|null  $earliest
     * @return void
     */
    public function prime(array $keys, ?CarbonImmutable $earliest = null): void
    {
        if ($this->store === null) {
            return;
        }

        $missing = \array_values(\array_filter(\array_unique($keys), fn (string $key): bool => !\array_key_exists($key, $this->observed)));
        $found   = $missing === [] ? [] : $this->store->lastObserved($missing);

        foreach ($missing as $key) {
            $this->observed[$key] = $found[$key] ?? false;
        }

        $from = $this->since ?? $earliest;

        if ($from === null || ($this->coveredFrom !== null && !$from->lessThan($this->coveredFrom))) {
            return;
        }

        $this->periods     = $this->store->coverage($from->subSeconds($this->grace()), $this->at);
        $this->coveredFrom = $from;
    }

    /**
     * Return the rows, each with what is known of its use, the routes not read
     * yet read in one lookup.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>  $rows
     * @return list<\SineMacula\Laravel\Authorization\Reviews\ReviewRow>
     */
    public function annotate(array $rows): array
    {
        $created = \array_filter(\array_map(static fn (ReviewRow $row): ?CarbonImmutable => $row->createdAt(), $rows));

        $this->prime(\array_map(GrantUsageKey::ofRow(...), $rows), $created === [] ? null : \min($created));

        return \array_map(fn (ReviewRow $row): ReviewRow => $row->withUsage($this->usageOf($row)), $rows);
    }

    /**
     * Determine whether the row's route shows no observed use in its window,
     * unused or unknown alike, as an unused review lists it.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @return bool
     */
    public function isUnobserved(ReviewRow $row): bool
    {
        return $this->usageOf($row)->status !== UsageStatus::USED;
    }

    /**
     * Return what is known of the row's use, from what was read of its route
     * and of the coverage.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @return \SineMacula\Laravel\Authorization\Reviews\RowUsage
     */
    public function usageOf(ReviewRow $row): RowUsage
    {
        if ($this->store === null || !$this->canReport($row)) {
            return RowUsage::unknown();
        }

        $observed = $this->observed[GrantUsageKey::ofRow($row)] ?? false;
        $use      = $observed instanceof ObservedUse && $observed->isOf($row->createdAt()) ? $observed : null;
        $from     = self::later($this->since, $row->createdAt());

        [$span, $isCovered] = $from === null ? [null, false] : $this->coverageOf($from);

        return new RowUsage($this->statusOf($use, $from, $isCovered), $use?->lastObservedAt, $span?->from, $span === null ? null : self::earlier($span->until, $this->at));
    }

    /**
     * Return the status of a route given its use through the grant as it
     * stands, the start of its window and whether coverage reaches the whole
     * window: used when it was observed in a bucket that ends after the window
     * starts, else unused when the window is covered, else unknown.
     *
     * @param  \SineMacula\Laravel\Authorization\Usage\ObservedUse|null  $use
     * @param  \Carbon\CarbonImmutable|null  $from
     * @param  bool  $isCovered
     * @return \SineMacula\Laravel\Authorization\Reviews\Enums\UsageStatus
     */
    private function statusOf(?ObservedUse $use, ?CarbonImmutable $from, bool $isCovered): UsageStatus
    {
        $isUsed = $use !== null && ($from === null || $use->lastObservedAt->getTimestamp() + $this->interval > $from->getTimestamp());

        return match (true) {
            $isUsed    => UsageStatus::USED,
            $isCovered => UsageStatus::UNUSED,
            default    => UsageStatus::UNKNOWN,
        };
    }

    /**
     * Return the latest period that overlaps the window from the instant to the
     * review's, and whether the periods cover the whole window, each taken to
     * reach two intervals past its end; an empty window is never covered.
     *
     * @param  \Carbon\CarbonImmutable  $from
     * @return array{\SineMacula\Laravel\Authorization\Usage\CoveragePeriod|null, bool}
     */
    private function coverageOf(CarbonImmutable $from): array
    {
        $reached = $from->getTimestamp();
        $latest  = null;

        foreach ($this->periods as $period) {
            $start = $period->from->getTimestamp();
            $end   = $period->until->getTimestamp() + $this->grace();

            if ($end <= $from->getTimestamp() || !$period->from->lessThan($this->at)) {
                continue;
            }

            $latest  = $period;
            $reached = $start <= $reached ? \max($reached, $end) : $reached;
        }

        return [$latest, $from->lessThan($this->at) && $reached >= $this->at->getTimestamp()];
    }

    /**
     * Determine whether the row's source can report its use: a grant, never a
     * role's edge or attachment, to a grantee whose grants of the kinds the
     * route rests on the package resolves.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewRow  $row
     * @return bool
     */
    private function canReport(ReviewRow $row): bool
    {
        $needs = self::needsOf($row->sourceKind);

        foreach ($needs as $kind) {
            $this->reporting[$row->grantee->type . '|' . $kind] ??= self::isReported($row->grantee->type, $kind);
        }

        return $needs !== [] && \array_filter($needs, fn (string $kind): bool => !$this->reporting[$row->grantee->type . '|' . $kind]) === [];
    }

    /**
     * Return the kinds of grant a route of the kind rests on, whose resolution
     * must report its use: a permission's, a policy's, or both for a role,
     * which carries either; none for a role's edge or attachment.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $kind
     * @return list<string>
     */
    private static function needsOf(SourceKind $kind): array
    {
        return match ($kind) {
            SourceKind::PERMISSION_GRANT, SourceKind::ROLE_PERMISSION => ['permissions'],
            SourceKind::POLICY_ATTACHMENT, SourceKind::ROLE_POLICY    => ['policies'],
            SourceKind::ROLE_GRANT, SourceKind::ROLE_INHERITED        => ['permissions', 'policies'],
            default                                                   => [],
        };
    }

    /**
     * Determine whether the package resolves the grants of the kind of the
     * grantees of the morph type: their class uses the package's trait and
     * keeps its resolution as the trait's own, and, for policies, the package's
     * policy resolver is bound.
     *
     * @param  string  $type
     * @param  string  $kind
     * @return bool
     */
    private static function isReported(string $type, string $kind): bool
    {
        $class = Relation::getMorphedModel($type) ?? $type;

        [$trait, $method] = $kind === 'permissions' ? [HasPermissions::class, 'getPermissions'] : [HasPolicies::class, 'getPolicies'];

        if (!\class_exists($class) || !\in_array($trait, \class_uses_recursive($class), true)) {
            return false;
        }

        $isTraits = (new \ReflectionMethod($class, $method))->getFileName() === (new \ReflectionClass($trait))->getFileName();

        return $isTraits && ($kind === 'permissions' || Container::getInstance()->make(PolicyResolver::class) instanceof DefaultPolicyResolver);
    }

    /**
     * Return how far past its end a period is taken to reach: two intervals,
     * the most a flush or heartbeat may lag while tracking runs.
     *
     * @return int
     */
    private function grace(): int
    {
        return 2 * $this->interval;
    }

    /**
     * Return the later of the instants, either of which may be none.
     *
     * @param  \Carbon\CarbonImmutable|null  $one
     * @param  \Carbon\CarbonImmutable|null  $other
     * @return \Carbon\CarbonImmutable|null
     */
    private static function later(?CarbonImmutable $one, ?CarbonImmutable $other): ?CarbonImmutable
    {
        if ($one === null || $other === null) {
            return $one ?? $other;
        }

        return $one->greaterThan($other) ? $one : $other;
    }

    /**
     * Return the earlier of the instants.
     *
     * @param  \Carbon\CarbonImmutable  $one
     * @param  \Carbon\CarbonImmutable  $other
     * @return \Carbon\CarbonImmutable
     */
    private static function earlier(CarbonImmutable $one, CarbonImmutable $other): CarbonImmutable
    {
        return $one->lessThan($other) ? $one : $other;
    }
}
