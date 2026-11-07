<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * A tenantless post whose integer key PHP may read otherwise than the database
 * holds it: on SQLite it is not the table's rowid, so it may hold a real number
 * or text, and on MySQL it is an unsigned `BIGINT`, beyond PHP's integers; for
 * query scoping tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LooseKeyedPost extends Model implements QueryableResource
{
    /** @var bool The key is given, never generated. */
    public $incrementing = false;

    /** @var bool The table has no timestamps. */
    public $timestamps = false;

    /** @var array<string> Every column may be filled. */
    protected $guarded = [];

    /** @var string|null Backing table. */
    protected $table = 'scoped_loose_posts';

    /**
     * Return where the records keep their tenant.
     *
     * @return \SineMacula\Laravel\Authorization\Support\ResourceTenancy
     */
    #[\Override]
    public static function resourceTenancy(): ResourceTenancy
    {
        return ResourceTenancy::tenantless();
    }
}
