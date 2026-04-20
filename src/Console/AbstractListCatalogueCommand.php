<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;

/**
 * Shared scaffolding for `authorization:list-roles` and
 * `authorization:list-permissions`. Both commands select a config-resolved
 * model, apply a `--guard` filter, include the companion relation count, and
 * render the result as a table with an empty-set fallback.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class AbstractListCatalogueCommand extends Command
{
    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $class = $this->modelClass();

        $query = $class::query()->withCount($this->countRelation());

        /** @var string|null $guard */
        $guard = $this->option('guard');

        if ($guard !== null && $guard !== '') {
            $query->where('guard', $guard);
        }

        /** @var \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model> $rows */
        // @phpstan-ignore staticMethod.dynamicCall
        $rows = $query->orderBy('name')->get();

        if ($rows->isEmpty()) {
            $this->info($this->emptyMessage());

            return self::SUCCESS;
        }

        $this->table(
            $this->headers(),
            $rows->map(fn (Model $row): array => $this->mapRow($row))->all(),
        );

        return self::SUCCESS;
    }

    /**
     * Return the fully-qualified Eloquent model class to list.
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model>
     */
    abstract protected function modelClass(): string;

    /**
     * Return the companion relation name passed to `withCount`.
     *
     * @return string
     */
    abstract protected function countRelation(): string;

    /**
     * Message rendered when no rows match the query.
     *
     * @return string
     */
    abstract protected function emptyMessage(): string;

    /**
     * Table header row.
     *
     * @return list<string>
     */
    abstract protected function headers(): array;

    /**
     * Map a single model row to a table row.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $row
     * @return list<string>
     */
    abstract protected function mapRow(Model $row): array;
}
