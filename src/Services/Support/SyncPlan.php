<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * What a sync of a grantee's rows of one kind works from, read afresh on each
 * try of the call: the scope it writes the rows in, whose tenant is the one it
 * replaces them in, the grantee's table there, the targets it keeps, keyed by
 * key, the keys the grantee holds there, and the scope each target listed with
 * a reach of its own (`Support\RoleReach`) is written in, keyed by key.
 *
 * A target listed with a reach of its own is written, decided and proposed to
 * the grant hook in the scope with that reach, and compared with it: held live
 * with the other reach, its reach is changed in place, keeping its expiry. Any
 * other target is written in the written scope, its reach written only where
 * the sync grants or re-arms it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SyncPlan
{
    /**
     * Create a new sync plan.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $written
     * @param  \SineMacula\Laravel\Authorization\Services\Support\GrantTable  $table
     * @param  array<string, \Illuminate\Database\Eloquent\Model>  $keep
     * @param  list<string>  $held
     * @param  array<string, \SineMacula\Laravel\Authorization\Support\GrantScope>  $reaches
     */
    public function __construct(

        /** The kind of row the sync replaces. */
        public GrantTarget $kind,

        /** The scope the sync writes its rows in, its tenant the one it replaces them in. */
        public GrantScope $written,

        /** The grantee's table in the written scope. */
        public GrantTable $table,

        /** The targets the sync keeps, keyed by key. */
        public array $keep,

        /** The keys the grantee holds in the scope. */
        public array $held = [],

        /** The scope each target listed with a reach of its own is written in, keyed by key. */
        public array $reaches = [],
    ) {}

    /**
     * Return the scope each target listed with a reach of its own is written
     * in, keyed by key, from each kept key and the reach its entry names, null
     * for none; a key listed with both reaches is refused, unless the written
     * scope is platform-wide, where every grant reaches below, so both entries
     * name the same reach.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $written
     * @param  list<array{string, bool|null}>  $listed
     * @return array<string, \SineMacula\Laravel\Authorization\Support\GrantScope>
     *
     * @throws \InvalidArgumentException
     */
    public static function reachesOf(GrantTarget $kind, GrantScope $written, array $listed): array
    {
        $reaches = [];

        foreach ($listed as [$key, $reach]) {
            if ($reach === null) {
                continue;
            }

            $scope = new GrantScope($written->tenant, $written->application, $reach || $written->tenant === null);

            if (($reaches[$key] ?? $scope)->includeSubtree !== $scope->includeSubtree) {
                throw new \InvalidArgumentException("The {$kind->value} [{$key}] is listed with both reaches.");
            }

            $reaches[$key] = $scope;
        }

        return $reaches;
    }

    /**
     * Return the keys of the targets the sync keeps.
     *
     * @return list<string>
     */
    public function kept(): array
    {
        return \array_values(\array_map(GrantChanges::key(...), $this->keep));
    }

    /**
     * Return the keys the grantee holds in the scope that the sync drops.
     *
     * @return list<string>
     */
    public function revoked(): array
    {
        return \array_values(\array_diff($this->held, $this->kept()));
    }

    /**
     * Return the scope the kept target of the key is written in: the one its
     * reach names, else the written scope.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    public function scopeOf(string $id): GrantScope
    {
        return $this->reaches[$id] ?? $this->written;
    }

    /**
     * Write each kept target, inside the caller's operation, as of the instant
     * given: a target listed with a reach of its own is re-armed with it and,
     * held live with the other reach, has its reach changed, keeping its
     * expiry; any other is re-armed. Return the events the writes dispatch,
     * each in the scope written and a changed reach with the expiry kept, and
     * the keys of each outcome, keyed by outcome. A row decided as held live
     * (the keys given) that the write changes throws
     * `DependencyChangedException`, so the call is tried again.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Support\Carbon  $now
     * @param  list<string>  $live
     * @return array{list<\SineMacula\Laravel\Authorization\Contracts\IdentityEvent>, array<string, list<string>>}
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     */
    public function write(Operation $operation, Reference $grantee, ?\DateTimeInterface $expiresAt, Carbon $now, array $live): array
    {
        $events  = [];
        $changed = [];

        foreach ($this->keep as $model) {
            $id     = GrantChanges::key($model);
            $change = $this->rearm($id, $expiresAt, $now);
            $events = [...$events, ...$this->kind->changeEvents($operation, $grantee, $model, $this->scopeOf($id), $change, $change->expiryAfter($expiresAt))];

            // A row decided as held live is never written back: one gone by the
            // write was not what was decided.
            if ($change->changesAnyOf($id, $live)) {
                throw DependencyChangedException::rows($this->kind->table());
            }

            $changed[$change->outcome->value][] = $id;
        }

        return [$events, $changed];
    }

    /**
     * Return the event of the revocation of each row the sync drops, in the
     * scope it was held in, with the reach it had (keyed by key).
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  array<string, bool>  $dropped
     * @return list<\SineMacula\Laravel\Authorization\Contracts\IdentityEvent>
     */
    public function revokedEvents(Operation $operation, Reference $grantee, array $dropped): array
    {
        $events = [];

        foreach ($this->kind->find($this->revoked()) as $model) {
            $held     = new GrantScope($this->written->tenant, $this->written->application, $dropped[GrantChanges::key($model)]);
            $events[] = $this->kind->revokedEvent($operation, $grantee, $model, $held);
        }

        return $events;
    }

    /**
     * Re-arm the kept row of the key as of the instant given: with the reach
     * its entry names, changing that of a live row held with the other, else
     * leaving a live row as it is.
     *
     * @param  string  $id
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Support\Carbon  $now
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantChange
     */
    private function rearm(string $id, ?\DateTimeInterface $expiresAt, Carbon $now): GrantChange
    {
        $reach = $this->reaches[$id] ?? null;

        return $reach === null ? $this->table->rearm($id, $expiresAt, $now) : $this->table->reaching($reach->includeSubtree)->rearmWithReach($id, $expiresAt, $now);
    }
}
