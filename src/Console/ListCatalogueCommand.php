<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * Shared body of the role and permission listing commands.
 *
 * An administrative view: it bypasses the tenant scope, so platform-wide and
 * tenant-owned records are listed alike, each with its ID, name, guard, owner
 * (`platform`, or the owning tenant as `{morphType}:{key}`), system flag, and
 * the count of its related records, which counts every related record whatever
 * its owner. An optional `--guard` filter restricts the listing to a single
 * guard name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class ListCatalogueCommand extends Command
{
    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $relation = $this->countedRelation();

        $query = $this->modelClass()::query()
            ->withoutGlobalScope(TenantScope::class)
            ->withCount([$relation => static fn (Builder $related): Builder => $related->withoutGlobalScope(TenantScope::class)]);

        /** @var string|null $guard */
        $guard = $this->option('guard');

        if ($guard !== null && $guard !== '') {
            $query->where('guard', $guard);
        }

        /** @var \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model> $records */
        // @phpstan-ignore staticMethod.dynamicCall
        $records = $query->orderBy('name')->get();

        if ($records->isEmpty()) {
            $this->info("No {$this->recordName()} found.");

            return self::SUCCESS;
        }

        $this->table(
            ['ID', 'Name', 'Guard', 'Owner', 'System', \ucfirst($relation)],
            $records->map(static fn (Model $record): array => self::row($record, $relation))->all(),
        );

        return self::SUCCESS;
    }

    /**
     * The configured model class whose records are listed.
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model>
     */
    abstract protected function modelClass(): string;

    /**
     * The relation whose records are counted for each listed record.
     *
     * @return string
     */
    abstract protected function countedRelation(): string;

    /**
     * The plural name of the listed records, for the empty-listing message.
     *
     * @return string
     */
    abstract protected function recordName(): string;

    /**
     * Build the table row for one record.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @param  string  $relation
     * @return list<string>
     */
    private static function row(Model $record, string $relation): array
    {
        /** @var string|null $tenantType */
        $tenantType = $record->getAttribute('tenant_type');

        /** @var string|null $tenantId */
        $tenantId = $record->getAttribute('tenant_id');

        /** @var int $count */
        $count = $record->getAttribute($relation . '_count');

        /** @var string $name */
        $name = $record->getAttribute('name');

        /** @var string|null $guard */
        $guard = $record->getAttribute('guard');

        return [
            (string) $record->getKey(), // @phpstan-ignore cast.string
            $name,
            $guard ?? '(any)',
            $tenantType === null ? 'platform' : "{$tenantType}:{$tenantId}",
            $record->getAttribute('is_system') ? 'Yes' : 'No',
            (string) $count,
        ];
    }
}
