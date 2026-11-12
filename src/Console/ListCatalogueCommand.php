<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\TenantColumns;

/**
 * Shared body of the role and permission listing commands.
 *
 * An administrative view: it bypasses the tenant scope, so platform-wide and
 * tenant-owned records are listed alike, each with its ID, name, guard, owner
 * (`platform`, the owning tenant as `{morphType}:{key}`, or, for a record
 * naming half a tenant, which the package never writes and which is neither the
 * platform's nor any tenant's, `malformed (tenant_type=…, tenant_id=…)` with
 * the missing half `null`), system flag, and the count of its related records,
 * which counts every related record whatever its owner. An optional `--guard`
 * filter restricts the listing to a single guard name. Each listing command
 * declares its name in `NAME` and the `authorization.models` key of what it
 * lists in `MODEL`, from which its signature, its description and the rest of
 * the listing are built.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class ListCatalogueCommand extends Command
{
    /** @var string The console command's name, which each listing command declares. */
    public const string NAME = '';

    /** @var 'permission'|'role' The `authorization.models` key of the listed model, which each listing command declares. */
    protected const string MODEL = 'role';

    /** @var array{permission: array{0: string, 1: string}, role: array{0: string, 1: string}} For each listed model's key: the relation whose records are counted, also the plural of the related records, and the plural name of the listed records. */
    private const array LISTINGS = [
        'permission' => ['roles', 'permissions'],
        'role'       => ['permissions', 'roles'],
    ];

    /**
     * Create the command, its signature built from its name, with an optional
     * `--guard` filter of the records it lists, and its description from the
     * model it lists.
     *
     * @return void
     */
    public function __construct()
    {
        $this->signature   = static::NAME . ' {--guard= : Filter ' . self::LISTINGS[static::MODEL][1] . ' by guard name}';
        $this->description = 'List every authorization ' . static::MODEL . ', platform-wide and tenant-owned, with its owner';

        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        [$relation, $plural] = self::LISTINGS[static::MODEL];

        /** @var class-string<\Illuminate\Database\Eloquent\Model> $class */
        $class = ModelClasses::get(static::MODEL);

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
            $this->info('No ' . $plural . ' found.');

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
            match (true) {
                TenantColumns::isHalf($tenantType, $tenantId) => TenantColumns::malformed($tenantType, $tenantId),
                $tenantType === null                          => 'platform',
                default                                       => "{$tenantType}:{$tenantId}",
            },
            $record->getAttribute('is_system') ? 'Yes' : 'No',
            $count,
        ];
    }
}
