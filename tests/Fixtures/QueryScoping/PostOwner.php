<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * A model owning the posts that share its title, one of its relations scoped in
 * its definition, for query scoping tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PostOwner extends Model
{
    /** @var bool The table has no timestamps. */
    public $timestamps = false;

    /** @var array<string> Every column may be filled. */
    protected $guarded = [];

    /** @var string|null Backing table. */
    protected $table = 'scoped_tickets';

    /**
     * Return the posts that share the owner's title.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany<\Tests\Fixtures\QueryScoping\ScopedPost, $this>
     */
    public function posts(): HasMany
    {
        return $this->hasMany(ScopedPost::class, 'title', 'title');
    }

    /**
     * Return the posts that share the owner's title which the subject may view,
     * scoped in the relation's definition.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany<\Tests\Fixtures\QueryScoping\ScopedPost, $this>
     */
    public function visiblePosts(): HasMany
    {
        return $this->hasMany(ScopedPost::class, 'title', 'title')->whereAuthorized('posts:view'); // @phpstan-ignore method.notFound
    }
}
