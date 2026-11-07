<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Scopes\AuthorizedScope;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * A post with an integer key whose tenant is in its tenant columns, every query
 * of which is scoped to the posts the current subject may view, by the
 * model-level scope, for query scoping tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GuardedPost extends Model implements QueryableResource
{
    /** @var string The action every query of the model is scoped to. */
    public const string ACTION = 'posts:view';

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
     * Scope every query of the model to the posts the current subject may view.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::addGlobalScope(new AuthorizedScope(self::ACTION));
    }
}
