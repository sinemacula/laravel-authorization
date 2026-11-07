<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;
use Tests\Fixtures\QueryRecorder;

/**
 * A post whose tenant is in its tenant columns, handing every base query
 * builder it creates to the `QueryRecorder`, for query scoping tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordedTenantPost extends Model implements QueryableResource
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
     * Create a new base query builder and record it.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    #[\Override]
    protected function newBaseQueryBuilder(): Builder
    {
        $query = parent::newBaseQueryBuilder();

        QueryRecorder::record($query);

        return $query;
    }
}
