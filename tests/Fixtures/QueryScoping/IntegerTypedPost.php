<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * A tenantless post whose key type is spelt `integer`, for query scoping tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IntegerTypedPost extends Model implements QueryableResource
{
    /** @var bool The table has no timestamps. */
    public $timestamps = false;

    /** @var string The key type, as Laravel's alias spells it. */
    protected $keyType = 'integer';

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
        return ResourceTenancy::tenantless();
    }
}
