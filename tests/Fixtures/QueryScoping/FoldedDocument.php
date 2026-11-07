<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * A tenantless document whose string key's collation folds case (`NOCASE` on
 * SQLite, `utf8mb4_unicode_ci` on MySQL, a nondeterministic collation on
 * PostgreSQL), so the key cannot be compared with a value byte for byte under
 * it; for query scoping tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FoldedDocument extends Model implements QueryableResource
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
    protected $table = 'scoped_folded_documents';

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
