<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * A tenantless post with an integer key, for query scoping tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScopedPost extends Model implements QueryableResource
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
        return ResourceTenancy::tenantless();
    }
}
