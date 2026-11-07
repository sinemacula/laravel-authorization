<?php

declare(strict_types = 1);

namespace Tests\Fixtures\BulkChecks;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * A post whose tenant is in its tenant columns, read through the package's
 * tenant scope, so a query on it sees only the rows of the tenant the scope
 * holds at the time, its ancestors and the platform, for bulk check tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GuardedPost extends Model implements QueryableResource
{
    /** @var bool The table has no timestamps. */
    public $timestamps = false;

    /** @var array<string> Every column may be filled. */
    protected $guarded = [];

    /** @var string|null Backing table. */
    protected $table = 'scoped_posts';

    /**
     * Return where the records keep their tenant.
     *
     * @return \SineMacula\Laravel\Authorization\Support\ResourceTenancy
     */
    #[\Override]
    public static function resourceTenancy(): ResourceTenancy
    {
        return ResourceTenancy::columns();
    }

    /**
     * Scope every query to the tenant the tenant scope holds.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::addGlobalScope(new TenantScope);
    }
}
