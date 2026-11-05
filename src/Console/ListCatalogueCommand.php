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
    /** @var string The `authorization.models` key of the listed model. */
    protected const string MODEL = '';

    /** @var class-string<\Illuminate\Database\Eloquent\Model> The model listed when none is configured. */
    protected const string DEFAULT_MODEL = Model::class;

    /** @var string The relation whose records are counted, also the plural of the related records. */
    protected const string COUNTED = '';

    /** @var string The plural name of the listed records, for the empty-listing message. */
    protected const string RECORDS = '';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $relation = static::COUNTED;

        /** @var class-string<\Illuminate\Database\Eloquent\Model> $class */
        $class = config('authorization.models.' . static::MODEL, static::DEFAULT_MODEL);

        $query = $class::query()
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
            $this->info('No ' . static::RECORDS . ' found.');

            return self::SUCCESS;
        }

        $this->table(
            ['ID', 'Name', 'Guard', 'Owner', 'System', \ucfirst($relation)],
            $records->map(static fn (Model $record): array => self::row($record, $relation))->all(),
        );

        return self::SUCCESS;
    }

    /**
     * Build the table row for one record.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @param  string  $relation
     * @return list<mixed>
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
            $record->getKey(),
            $name,
            $guard ?? '(any)',
            $tenantType === null ? 'platform' : "{$tenantType}:{$tenantId}",
            $record->getAttribute('is_system') ? 'Yes' : 'No',
            $count,
        ];
    }
}
