<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exclusions\Support;

use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Exclusions\ConflictReport;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionConflict;
use SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute;
use SineMacula\Laravel\Authorization\Reviews\Support\TenantRelations;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The conflict report of pairs of mutually exclusive roles (AUTHZ-11.8, N135,
 * N136): who holds both roles of each pair where their reach overlaps.
 *
 * Two routes, one to each role, overlap where a check sees both roles held (see
 * `ExclusionRoute::$reach`): their applications meet, either for every
 * application or both the same one, and their tenants meet, either
 * platform-wide, both the same tenant, or one reaching below a tenant the other
 * is in or below, per the bound tenant tree (see
 * `TenantRelations::canHoldTogether()`). Disjoint tenants never conflict, and
 * nor does a grant limited to its own tenant against one below it.
 *
 * A holder's own routes are weighed against each other, and so are a
 * principal's together with its identity's, as a check weighs them: the
 * identity directory lists each holder's principals (N81), and a principal that
 * holds one role itself and the other through its identity, when the identity's
 * grants reach it (both machines or neither, see
 * `SubjectGrants::grantingIdentity()`), conflicts, the identity named. A
 * sibling principal of the same identity never counts, and an identity that
 * holds both itself is reported as its own holder.
 *
 * The holdings of every role of every pair are read together (see
 * `ExclusionHoldings`), in a fixed number of queries, read locked for a
 * declaration and for a write the exclusion guard weighs (see
 * `ExclusionGuard`). Whether the tenant of one route lies within the tenant of
 * a route to the other role reaching below it is settled for every pair of
 * routes together, a chunk of them a query (see
 * `TenantRelations::settleWithin()`), never once for each holder or tenant; the
 * identity directory, the application's seam, is asked once for each holder of
 * a role of a pair.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConflictReader
{
    /** @var \SineMacula\Laravel\Authorization\Reviews\Support\TenantRelations Whether two scopes hold together, as the tree answers. */
    private TenantRelations $relations;

    /** @var array<string, list<\SineMacula\Laravel\Authorization\Support\Reference>> The principals of each holder that its grants reach, by the holder's key. */
    private array $principals = [];

    /** @var array<string, true> The holders whose principals the directory listed incompletely, by key. */
    private array $incomplete = [];

    /**
     * Create a new conflict reader.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\IdentityDirectory  $directory
     */
    public function __construct(

        /** The directory each holder's principals are listed by. */
        private readonly IdentityDirectory $directory,
    ) {
        $this->relations = new TenantRelations;
    }

    /**
     * Return the conflict report of each pair, in the order given, each pair
     * its two roles in the pair's order, read under locks when asked (see
     * `ExclusionHoldings`); given a write, as it would leave the holdings, each
     * report keeping only the conflicts the write creates.
     *
     * @param  list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference}>  $pairs
     * @param  bool  $isLocked
     * @param  \SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionWrite|null  $write
     * @return list<\SineMacula\Laravel\Authorization\Exclusions\ConflictReport>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     * @throws \UnexpectedValueException
     */
    public function read(array $pairs, bool $isLocked = false, ?ExclusionWrite $write = null): array
    {
        $roles = [];

        foreach ($pairs as [$role, $excluded]) {
            $roles[$role->id]     = $role->id;
            $roles[$excluded->id] = $excluded->id;
        }

        $keys     = \array_values($roles);
        $holdings = ExclusionHoldings::read($keys, $this->relations, $isLocked, $write);

        $this->learn($holdings->holders(...$keys));

        $candidates = \array_map(fn (array $pair): array => $this->candidates($pair[0]->id, $pair[1]->id, $holdings), $pairs);

        $this->settle(\array_merge(...$candidates));

        return \array_map(fn (array $pair, array $sets): ConflictReport => $this->report($pair[0], $pair[1], $sets, $holdings, $write), $pairs, $candidates);
    }

    /**
     * Return the conflict report of one pair from its sets of routes.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $role
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $excluded
     * @param  list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null, 2: list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>, 3: list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>}>  $candidates
     * @param  \SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionHoldings  $holdings
     * @param  \SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionWrite|null  $write
     * @return \SineMacula\Laravel\Authorization\Exclusions\ConflictReport
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    private function report(Reference $role, Reference $excluded, array $candidates, ExclusionHoldings $holdings, ?ExclusionWrite $write): ConflictReport
    {
        $conflicts = [];

        foreach ($candidates as [$holder, $identity, $firsts, $seconds]) {
            \array_push($conflicts, ...$this->overlapping($holder, $identity, $firsts, $seconds));
        }

        if ($write !== null) {
            $conflicts = \array_values(\array_filter($conflicts, $write->makes(...)));
        }

        \usort($conflicts, static fn (ExclusionConflict $one, ExclusionConflict $other): int => $one->orderKey() <=> $other->orderKey());

        $isComplete = \array_intersect_key($this->incomplete, $holdings->holders($role->id, $excluded->id)) === [];

        return new ConflictReport($role, $excluded, $conflicts, $isComplete);
    }

    /**
     * Return the sets of routes to weigh against each other for the pair: each
     * holder's own routes to each role, and, for each principal of a holder,
     * its own routes to one role against the holder's grants of the other, each
     * way round, since no break-glass activation reaches a principal through
     * its identity.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @param  string  $role
     * @param  string  $excluded
     * @param  \SineMacula\Laravel\Authorization\Exclusions\Support\ExclusionHoldings  $holdings
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null, 2: list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>, 3: list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>}>
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    private function candidates(string $role, string $excluded, ExclusionHoldings $holdings): array
    {
        $candidates = [];

        foreach ($holdings->holders($role, $excluded) as $key => $holder) {
            $candidates[] = [$holder, null, $holdings->of($role, $holder), $holdings->of($excluded, $holder)];

            foreach ($this->principals[$key] ?? [] as $principal) {
                $candidates[] = [$principal, $holder, $holdings->of($role, $principal), $holdings->of($excluded, $holder, isIdentity: true)];
                $candidates[] = [$principal, $holder, $holdings->of($role, $holder, isIdentity: true), $holdings->of($excluded, $principal)];
            }
        }

        return $candidates;
    }

    /**
     * Return a conflict for each route to the first role that overlaps a route
     * to the second.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $holder
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $identity
     * @param  list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>  $firsts
     * @param  list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>  $seconds
     * @return list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionConflict>
     */
    private function overlapping(Reference $holder, ?Reference $identity, array $firsts, array $seconds): array
    {
        $conflicts = [];

        foreach ($firsts as $first) {
            $overlapping = \array_filter($seconds, fn (ExclusionRoute $second): bool => $this->isOverlapping($first, $second));

            foreach ($overlapping as $second) {
                $conflicts[] = new ExclusionConflict($holder, $identity, $first, $second);
            }
        }

        return $conflicts;
    }

    /**
     * Determine whether a check sees both routes' roles held somewhere: where
     * they are held, their applications meet, and so do their tenants.
     *
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute  $one
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute  $other
     * @return bool
     */
    private function isOverlapping(ExclusionRoute $one, ExclusionRoute $other): bool
    {
        $first  = $one->scope->application;
        $second = $other->scope->application;

        return ($first === null || $second === null || $first === $second) && $this->relations->canHoldTogether($one->reach, $other->reach);
    }

    /**
     * Settle, in a fixed number of queries, whether each tenant a route of the
     * candidates holds in lies within the tenant of a route to the other role
     * reaching below it, so no pair of routes is asked of the tree alone.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @param  list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference|null, 2: list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>, 3: list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>}>  $candidates
     * @return void
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @throws \UnexpectedValueException
     */
    private function settle(array $candidates): void
    {
        $questions = [];

        foreach ($candidates as [, , $firsts, $seconds]) {
            foreach ($firsts as $first) {
                \array_push($questions, ...self::questions($first, $seconds));
            }
        }

        $this->relations->settleWithin($questions);
    }

    /**
     * Return the pairs of a tenant and an ancestor whether the route overlaps
     * each of the others turns on: where one of the two reaches below its
     * tenant, the other's tenant within it, neither at the platform.
     *
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute  $route
     * @param  list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute>  $others
     * @return list<array{0: \SineMacula\Laravel\Authorization\Support\Reference, 1: \SineMacula\Laravel\Authorization\Support\Reference}>
     */
    private static function questions(ExclusionRoute $route, array $others): array
    {
        $questions = [];
        $one       = $route->reach;

        foreach ($others as $other) {
            [$first, $second] = [$one->tenant, $other->reach->tenant];

            if ($first === null || $second === null) {
                continue;
            }

            if ($one->includeSubtree) {
                $questions[] = [$second, $first];
            }

            if (!$other->reach->includeSubtree) {
                continue;
            }

            $questions[] = [$first, $second];
        }

        return $questions;
    }

    /**
     * Learn the principals of each holder, asking the directory once for each:
     * those that are not the holder itself and that the holder's grants reach,
     * both machines or neither; and which holders' lists were incomplete. A
     * principal that holds neither role has no route to weigh.
     *
     * @param  array<string, \SineMacula\Laravel\Authorization\Support\Reference>  $holders
     * @return void
     */
    private function learn(array $holders): void
    {
        foreach ($holders as $key => $holder) {
            $listed = $this->directory->principalsOf($holder);

            if (!$listed->isComplete) {
                $this->incomplete[$key] = true;
            }

            $isMachine = ExclusionHoldings::isMachine($holder);
            $reached   = static fn (Reference $principal): bool => ExclusionHoldings::key($principal) !== $key && ExclusionHoldings::isMachine($principal) === $isMachine;

            $this->principals[$key] = \array_values(\array_filter($listed->principals, $reached));
        }
    }
}
