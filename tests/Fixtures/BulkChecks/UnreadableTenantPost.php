<?php

declare(strict_types = 1);

namespace Tests\Fixtures\BulkChecks;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * A post whose tenant is in its tenant columns, but whose tenant key, once
 * read, holds a number with a fraction when the column holds `unreadable`, as a
 * column of another type would, so its tenant cannot be read, for bulk check
 * tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UnreadableTenantPost extends Model implements QueryableResource
{
    /** @var string The tenant key that is read back as a number with a fraction. */
    public const string UNREADABLE = 'unreadable';

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
     * Read the unreadable tenant key back as a number with a fraction.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::retrieved(static function (self $post): void {
            if (($post->getAttributes()['tenant_id'] ?? null) !== self::UNREADABLE) {
                return;
            }

            $post->setRawAttributes([...$post->getAttributes(), 'tenant_id' => 1.5], true);
        });
    }
}
