<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * A queryable post the refused fixture models extend, tenantless unless a test
 * declares other tenant columns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class AbstractQueryablePost extends Model implements QueryableResource
{
    /** @var \SineMacula\Laravel\Authorization\Support\ResourceTenancy|null The tenancy every such post declares; null for none. */
    public static ?ResourceTenancy $tenancy = null;

    /** @var bool The table has no timestamps. */
    public $timestamps = false;

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
        return self::$tenancy ?? ResourceTenancy::tenantless();
    }
}
