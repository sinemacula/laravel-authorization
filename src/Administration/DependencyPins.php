<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Enums\DependencyPhase;
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * What one try of a delegated operation's decisions read, locked and pinned, so
 * the operation never commits on authority that changed under it (AUTHZ-11.1,
 * the concurrency protocol).
 *
 * Every set of rows a decision depends on is read with `lockForUpdate()` on the
 * write connection before the decision reads it, and the digest of what was
 * read is kept: the actor's authority first, once, then the records the
 * operation changes, the grantee's grant rows among them, then the holders and
 * the resource policies a decision reaches, as it reads them, and last, once
 * every decision is made, the grants a grant hook's coverage check reads again
 * (see `lockCoverage()`). A service locks what it changes before it reads it,
 * so what it decides on is what the locks hold; a record it read before the
 * lock, such as a role looked up by name, is read again under the lock and
 * compared, so one that changed in between has the operation tried again rather
 * than decided on what the row no longer holds. A set a decision reaches is
 * locked only when it is no larger than
 * `authorization.administration.max_impact`; a larger one is refused as
 * unprovable without being locked.
 *
 * The parts are locked in that order within one operation, each query's keys
 * sorted, and a part locked after a later one is a mistake, refused with
 * `LogicException`. That order does not stop two operations deadlocking: one
 * operation's actor may be the other's target, or one's held role the other's
 * granted one, so each may hold a row the other waits for. PostgreSQL and MySQL
 * detect the deadlock and refuse one of the two, which is tried again when it
 * opened the transaction (see `ConflictRetries`). The tenant tree is the
 * application's and cannot be locked, so the chain of each tenant the operation
 * holds in is read afresh and kept, and a `treeChanged()` reported meanwhile
 * marks the operation moved.
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
        $grantees            = \array_filter([$this->operation->actor, $this->operation->identity]);

        AuthorityRows::in($this, DependencyPhase::ACTOR)
            ->grantees(...$grantees)
            ->tenants($tenant === null ? null : new Reference(...$tenant))
            ->resources(OperationResource::TYPE)
            ->lock();
    }

    /**
     * Lock the actor's authority, when it is not locked yet, then the grant
     * rows of each grantee and what they hold, or, for a role, its chain and
     * what it carries, before the service reads them; a role, permission or
     * policy given as a model is then compared with its row as locked (see
     * `assertStored()`).
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  ...$grantees
     * @return void
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     */
    public function lockGrantees(Model|Reference ...$grantees): void
    {
        $this->lockActor();

        $rows = AuthorityRows::in($this, DependencyPhase::TARGET);

        foreach ($grantees as $grantee) {
            $reference = Reference::of($grantee);

            OperationGrantee::isRole($reference) ? $rows->roles($reference->id) : $rows->grantees($reference);
        }

        $rows->lock();

        foreach ($grantees as $grantee) {
            self::assertStored($grantee instanceof Model ? $grantee : null);
        }
    }

    /**
     * Lock the actor's authority, when it is not locked yet, then what the
     * changes change (see `AuthorityRows::change()`), and compare each role,
     * permission or policy a change hands out, takes away or redefines, as the
     * service read it, with its row as locked (see `assertStored()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  ...$changes
     * @return void
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     */
    public function lockChanges(OperationResource ...$changes): void
    {
        $this->lockActor();

        $rows = AuthorityRows::in($this, DependencyPhase::TARGET);

        foreach ($changes as $change) {
            $rows->change($change);
        }

        $rows->lock();

        foreach ($changes as $change) {
            self::assertStored($change->change?->target);
            self::assertStored($change->definition?->record);
        }
    }

    /**
     * Lock the actor's authority, when it is not locked yet, then what a
     * guardrail change changes: the policy's row, when it is saved, and the
     * guardrails of the tenant, or of the platform when it is null, and of the
     * scopes above it.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return void
     *
     * @throws \LogicException
     */
    public function lockGuardrail(Policy $policy, ?Reference $tenant): void
    {
        $this->lockActor();

        AuthorityRows::in($this, DependencyPhase::TARGET)->tenants($tenant)->record($policy)->lock();
    }

    /**
     * Lock the rows each query selects, for the part given, sorted by query,
     * and pin what was read, with a copy of the query, so a caller that goes on
     * to change its own never changes what is read again; return the rows,
     * those of a query pinned before as they were read then.
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
            $this->rows[$key] ??= [clone $query, ...self::read($query, true)];
            $rows = [...$rows, ...$this->rows[$key][2]];
        }

        return $rows;
    }

    /**
     * Lock the rows the query selects, for the part given, and pin what was
     * read, when there are no more than the limit; return them, or null when
     * there are more, having locked no more than one over the limit. A set over
     * the limit is never pinned: what reads it refuses the change as
     * unprovable, so nothing it read needs to stay as it was.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\DependencyPhase  $phase
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  int  $limit
     * @return list<array<string, mixed>>|null
     *
     * @throws \LogicException
     */
    public function lockWithin(DependencyPhase $phase, Builder $query, int $limit): ?array
    {
        $this->enter($phase);

        $bounded = (clone $query)->limit($limit + 1);
        $key     = self::keyOf($bounded);
        $read    = $this->rows[$key] ?? [$bounded, ...self::read($bounded, true)];

        if (\count($read[2]) > $limit) {
            return null;
        }

        $this->rows[$key] = $read;

        return $read[2];
    }

    /**
     * Return the keys in the column of the rows the query selects, each once,
     * or null when it selects more rows than the limit, reading no more than
     * one over it. Inside a delegated operation the rows are locked and pinned
     * when they are within the limit (see `lockWithin()`), so a row added or
     * removed meanwhile is noticed before the write; elsewhere they are read as
     * they stand, so a screen's check reads what the service's does.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $column
     * @param  int  $limit
     * @return list<string>|null
     *
     * @throws \LogicException
     */
    public static function keysWithin(Builder $query, string $column, int $limit): ?array
    {
        $pins = OperationScope::pins();
        $rows = $pins === null ? self::read((clone $query)->limit($limit + 1), false)[1] : $pins->lockWithin(DependencyPhase::HOLDERS, $query, $limit);

        if ($rows === null || \count($rows) > $limit) {
            return null;
        }

        /** @var list<string> $keys */
        $keys = \array_column($rows, $column);

        return \array_values(\array_unique($keys));
    }

    /**
     * Lock the rows the query selects, for the coverage part, and return them:
     * the grants a grant hook's coverage check reads again once every decision
     * is made (see `Hooks\WideningPhase`). Inside a delegated operation they
     * are locked and pinned through its pins, after every other part; inside a
     * trusted one, which has no pins, they are read under the lock directly.
     * Either way the read sees the latest committed rows, whatever snapshot the
     * transaction reads otherwise, and the rows found stay locked until it
     * ends.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return list<array<string, mixed>>
     *
     * @throws \LogicException
     */
    public static function lockCoverage(Builder $query): array
    {
        $pins = OperationScope::pins();

        return $pins === null ? self::read($query, true)[1] : $pins->lock(DependencyPhase::COVERAGE, $query);
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
     * Throw when the role, permission or policy, as the service read it, is no
     * longer its row as stored, read again under the lock: a rank, a document,
     * a guard or an owner changed, or the row is gone, between the service's
     * read and the lock, so the operation is tried again rather than decided on
     * what the row no longer holds. Every column the record and the row both
     * hold is compared, as read from the database; any other model, or a record
     * not saved yet, is not compared.
     *
     * @param  \Illuminate\Database\Eloquent\Model|null  $record
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     */
    private static function assertStored(?Model $record): void
    {
        if (!($record instanceof Role || $record instanceof Permission || $record instanceof Policy) || !$record->exists) {
            return;
        }

        $row  = $record->newQueryWithoutScopes()->useWritePdo()->whereKey($record->getKey())->lockForUpdate()->toBase()->first();
        $read = $record->getRawOriginal();

        if ($row === null) {
            throw DependencyChangedException::rows($record->getTable());
        }

        foreach ((array) $row as $column => $value) {
            if (\array_key_exists($column, $read) && $read[$column] !== $value) {
                throw DependencyChangedException::rows($record->getTable());
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
            $keyed[self::keyOf($query)] = $query;
        }

        \ksort($keyed, \SORT_STRING);

        return $keyed;
    }

    /**
     * Return the key a query is pinned by: its table, SQL and bindings.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return string
     */
    private static function keyOf(Builder $query): string
    {
        return \serialize([$query->from, $query->toSql(), $query->getBindings()]);
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
        $rows  = \array_map(static fn (object $row): array => (array) $row, $read->get()->all());
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
        return TenantChain::of($tenant, TenantChain::tree(), isFresh: true)->tenants;
    }
}
