<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services\Support;

use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;

/**
 * Removes the expired rows a query reads, a chunk at a time, each chunk one
 * operation, through the removal given for the shape of row the query reads.
 *
 * Every row read is removed, or has been re-armed or removed since, so a later
 * read never returns it and the sweep ends.
 *
 * @template TRow of array<string, mixed>
 * @template TKind of \SineMacula\Laravel\Authorization\Enums\GrantTarget|null
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExpiredSweep
{
    /**
     * Create a new expired sweep.
     *
     * @param  \Closure(list<TRow>, \SineMacula\Laravel\Authorization\Support\Operation, TKind): int  $remove
     * @param  TKind  $kind
     */
    public function __construct(

        /** Removes one chunk of rows, reporting each removed, and returns how many were removed. */
        private \Closure $remove,

        /** The kind of grant the rows hold, handed to the removal; null for a role's grants of permissions. */
        private ?GrantTarget $kind = null,
    ) {}

    /**
     * Remove the expired rows the query reads, with the columns, a chunk at a
     * time, and return how many were removed.
     *
     * @param  \Illuminate\Database\Query\Builder  $expired
     * @param  list<string>  $columns
     * @param  int  $chunk
     * @return int
     *
     * @throws \Throwable
     */
    public function run(Builder $expired, array $columns, int $chunk): int
    {
        $removed = 0;

        do {
            /** @var list<TRow> $rows */
            $rows = (clone $expired)->limit($chunk)->get($columns)->map(static fn (object $row): array => (array) $row)->all();

            $removed += OperationScope::run(Operation::begin(), fn (Operation $operation): int => ($this->remove)($rows, $operation, $this->kind));
        } while (\count($rows) === $chunk);

        return $removed;
    }
}
