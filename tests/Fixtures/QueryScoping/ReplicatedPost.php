<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * A post kept on the `authorization` connection, beside the authorization
 * tables, outside the transaction every test runs in, so a test can give that
 * connection a separate read connection, for query scoping tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReplicatedPost extends Model implements QueryableResource
{
    /** @var string The connection the model is kept on. */
    public const string CONNECTION = 'authorization';

    /** @var bool The table has no timestamps. */
    public $timestamps = false;

    /** @var string|\UnitEnum|null The connection the model is kept on. */
    protected $connection = self::CONNECTION;

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
}
