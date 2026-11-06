<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * A tenantless document keyed by a string column that may hold any value, for
 * query scoping tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScopedDocument extends Model implements QueryableResource
{
    /** @var bool The key is given, never generated. */
    public $incrementing = false;

    /** @var bool The table has no timestamps. */
    public $timestamps = false;

    /** @var string Primary key column. */
    protected $primaryKey = 'code';

    /** @var string Primary key type. */
    protected $keyType = 'string';

    /** @var array<string> Every column may be filled. */
    protected $guarded = [];

    /** @var string|null Backing table. */
    protected $table = 'scoped_documents';

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
