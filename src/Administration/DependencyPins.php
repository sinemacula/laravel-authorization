<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Enums\DependencyPhase;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * What one try of a delegated operation's decisions read, locked and pinned, so
 * the operation never commits on authority that changed under it (AUTHZ-11.1,
 * the concurrency protocol).
 *
 * Every set of rows a decision depends on is read with `lockForUpdate()` on the
 * write connection before the decision reads it, and the digest of what was
 * read is kept: the actor's authority first, once, when the operation makes its
 * first decision, then the records it changes, then the holders a change
 * reaches, each part in the order `AuthorityRows` documents and each set within
 * one call sorted by its query, so two operations take their locks in the same
 * order and never deadlock on each other over the same parts (see
 * `DependencyPhase`; a part locked after a later one is a mistake, refused with
 * `LogicException`). The tenant tree is the application's and cannot be locked,
 * so the chain of each tenant the operation holds in is read afresh and kept,
 * and a `treeChanged()` reported meanwhile marks the operation moved.
 *
 * Once every change is decided and before anything is written, `validate()`
 * reads every set again, once as the decision would read it and once under the
 * lock, and every chain afresh, and throws `DependencyChangedException` when
 * any differs from what was pinned, or the tree was reported moved: a row the
 * locks could not hold, one inserted where none was, or one a snapshot older
 * than the locks shows, so the operation is rolled back and tried again (see
 * `ConflictRetries`).
 *
 * The locks hold until the operation's transaction ends, so on PostgreSQL and
 * MySQL a concurrent write of a locked row waits for the operation, and only an
 * insertion the locks do not cover, or a read made before them, can still
 * differ. SQLite serialises writers and compiles no row lock, so there the
 * locks are a no-op and the second read is what catches a change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DependencyPins
{
    /** @var \SineMacula\Laravel\Authorization\Enums\DependencyPhase The latest part locked so far. */
    private DependencyPhase $phase = DependencyPhase::ACTOR;

    /** @var bool Whether the actor's authority has been locked. */
    private bool $isActorLocked = false;

    /** @var array<string, array{\Illuminate\Database\Query\Builder, string, list<array<string, mixed>>}> Each set of rows pinned, by its query, with the digest and the rows read under the lock. */
    private array $rows = [];

    /** @var array<string, array{\SineMacula\Laravel\Authorization\Support\Reference, string}> Each tenant whose chain is pinned, by its key, with the chain as read. */
    private array $chains = [];

    /** @var bool Whether the tenant tree was reported changed since the first decision. */
    private bool $isTreeChanged = false;

    /**
     * Create the pins of one try of the operation, holding nothing yet.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     */
    public function __construct(

        /** The delegated operation whose decisions are pinned. */
        private readonly Operation $operation,
    ) {}

    /**
     * Lock the actor's authority, once: its principal's and identity's grant
     * rows, their roles and the chain above them, the boundaries, the
     * guardrails in the reach of the request's tenant, the resource policies of
     * the operation type, and the permissions and policies all of those name.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function lockActor(): void
    {
        if ($this->isActorLocked) {
            return;
        }

        $this->isActorLocked = true;
        $tenant              = TenantScope::currentTenant();
        $grantees            = \array_values(\array_filter([$this->operation->actor, $this->operation->identity]));

        AuthorityRows::in($this, DependencyPhase::ACTOR)
            ->grantees(...$grantees)
            ->tenants($tenant === null ? null : new Reference(...$tenant))
            ->resources(OperationResource::TYPE)
            ->lock();
    }

    /**
     * Lock the actor's authority, when it is not locked yet, then what the
     * changes change (see `AuthorityRows::change()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  ...$changes
     * @return void
     *
     * @throws \LogicException
     */
    public function lockChanges(OperationResource ...$changes): void
    {
        $this->lockActor();

        $rows = AuthorityRows::in($this, DependencyPhase::TARGET);

        foreach ($changes as $change) {
            $rows->change($change);
        }

        $rows->lock();
    }

    /**
     * Lock the actor's authority, when it is not locked yet, then what a
     * guardrail change changes: the policy's row, when it has a key, and the
     * guardrails of the tenant, or of the platform when it is null, and of the
     * scopes above it.
     *
     * @param  string|null  $policy
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return void
     *
     * @throws \LogicException
     */
    public function lockGuardrail(?string $policy, ?Reference $tenant): void
    {
        $this->lockActor();

        AuthorityRows::in($this, DependencyPhase::TARGET)->tenants($tenant)->policies(...($policy === null ? [] : [$policy]))->lock();
    }

    /**
     * Lock the rows each query selects, for the part given, sorted by query,
     * and pin what was read; return the rows, those of a query pinned before as
     * they were read then.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\DependencyPhase  $phase
     * @param  \Illuminate\Database\Query\Builder  ...$queries
     * @return list<array<string, mixed>>
     *
     * @throws \LogicException
     */
    public function lock(DependencyPhase $phase, Builder ...$queries): array
    {
        $this->enter($phase);

        $rows = [];

        foreach (self::keyed($queries) as $key => $query) {
            $this->rows[$key] ??= [$query, ...self::read($query, true)];
            $rows = [...$rows, ...$this->rows[$key][2]];
        }

        return $rows;
    }

    /**
     * Pin the chain of each tenant, read afresh through the bound tenant tree,
     * for the part given, and return the tenants of every chain, each tenant
     * first and its ancestors after it; the platform has none.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\DependencyPhase  $phase
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  ...$tenants
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     *
     * @throws \LogicException
     */
    public function lockChains(DependencyPhase $phase, ?Reference ...$tenants): array
    {
        $this->enter($phase);

        $chained = [];

        foreach (\array_filter($tenants) as $tenant) {
            $chain = self::chainOf($tenant);

            $this->chains[\serialize([$tenant->type, $tenant->id])] ??= [$tenant, \serialize($chain)];

            $chained = [...$chained, ...$chain];
        }

        return $chained;
    }

    /**
     * Mark the tenant tree moved, so the operation is tried again rather than
     * written on the chains its decisions read.
     *
     * @return void
     */
    public function treeChanged(): void
    {
        $this->isTreeChanged = true;
    }

    /**
     * Return the latest part locked so far.
     *
     * @return \SineMacula\Laravel\Authorization\Enums\DependencyPhase
     */
    public function phase(): DependencyPhase
    {
        return $this->phase;
    }

    /**
     * Throw when anything the decisions read has changed since it was pinned:
     * the tree reported moved, a tenant's chain, or a set of rows read as the
     * decision reads it or under the lock.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     */
    public function validate(): void
    {
        if ($this->isTreeChanged) {
            throw DependencyChangedException::tree();
        }

        foreach ($this->chains as [$tenant, $chain]) {
            if (\serialize(self::chainOf($tenant)) !== $chain) {
                throw DependencyChangedException::tree();
            }
        }

        foreach ($this->rows as [$query, $digest]) {
            if (self::isChanged($query, $digest)) {
                throw DependencyChangedException::rows(\is_string($query->from) ? $query->from : $query->toSql());
            }
        }
    }

    /**
     * Determine whether the rows the query selects differ from the digest
     * pinned, read as a decision reads them or under the lock.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $digest
     * @return bool
     */
    private static function isChanged(Builder $query, string $digest): bool
    {
        return self::read($query, false)[0] !== $digest || self::read($query, true)[0] !== $digest;
    }

    /**
     * Enter the part given, refusing one before the latest part locked.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\DependencyPhase  $phase
     * @return void
     *
     * @throws \LogicException
     */
    private function enter(DependencyPhase $phase): void
    {
        if ($phase->value < $this->phase->value) {
            throw new \LogicException("The {$phase->name} dependencies of a delegated operation are locked after its {$this->phase->name} ones.");
        }

        $this->phase = $phase;
    }

    /**
     * Return the queries keyed by their table, SQL and bindings, sorted by that
     * key.
     *
     * @param  array<array-key, \Illuminate\Database\Query\Builder>  $queries
     * @return array<string, \Illuminate\Database\Query\Builder>
     */
    private static function keyed(array $queries): array
    {
        $keyed = [];

        foreach ($queries as $query) {
            $keyed[\serialize([$query->from, $query->toSql(), $query->getBindings()])] = $query;
        }

        \ksort($keyed, \SORT_STRING);

        return $keyed;
    }

    /**
     * Read the rows the query selects on the write connection, under a lock
     * when asked, and return their digest, whatever order they came in, and the
     * rows.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  bool  $isLocked
     * @return array{string, list<array<string, mixed>>}
     */
    private static function read(Builder $query, bool $isLocked): array
    {
        $read = (clone $query)->useWritePdo();

        if ($isLocked) {
            $read->lockForUpdate();
        }

        /** @var list<array<string, mixed>> $rows */
        $rows  = \array_values(\array_map(static fn (object $row): array => (array) $row, $read->get()->all()));
        $lines = \array_map(\serialize(...), $rows);

        \sort($lines, \SORT_STRING);

        return [\hash('sha256', \implode("\n", $lines)), $rows];
    }

    /**
     * Return the tenant's chain, read afresh through the bound tenant tree.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    private static function chainOf(Reference $tenant): array
    {
        return TenantChain::of($tenant, TenantChain::tree(), false, true)->tenants;
    }
}
