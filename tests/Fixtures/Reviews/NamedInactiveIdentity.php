<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Reviews;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * An identity of the stub identities table that reports itself inactive when
 * its stored name is `inactive`, so a review that reads it back from the
 * database learns it is inactive.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NamedInactiveIdentity extends Model implements AuthorizableIdentity
{
    use HasAuthorization;

    /** @var bool Whether the key is an auto-incrementing integer. */
    public $incrementing = false;

    /** @var string The type of the key. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that are mass assignable. */
    protected $fillable = ['id', 'name'];

    /** @var string|null The table the identities are stored in. */
    protected $table = 'stub_identities';

    /**
     * Determine whether the identity is active: unless its name is `inactive`.
     *
     * @return bool
     */
    #[\Override]
    public function isAuthorizationActive(): bool
    {
        return $this->getAttribute('name') !== 'inactive';
    }
}
