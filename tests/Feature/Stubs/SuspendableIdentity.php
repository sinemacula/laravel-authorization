<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * A grantee the test can report inactive, as an application reports a suspended
 * user.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SuspendableIdentity extends Model implements AuthorizableIdentity
{
    use HasAuthorization;

    /** @var bool Whether the grantee is suspended; not a column. */
    public bool $suspended = false;

    /** @var bool Disable auto-incrementing — stubs use explicit IDs. */
    public $incrementing = false;

    /** @var string Primary key type. */
    protected $keyType = 'string';

    /** @var list<string> Mass-assignable attributes. */
    protected $fillable = ['id', 'name'];

    /** @var string|null Backing table. */
    protected $table = 'stub_identities';

    /**
     * Report the grantee inactive while it is suspended.
     *
     * @return bool
     */
    #[\Override]
    public function isAuthorizationActive(): bool
    {
        return !$this->suspended;
    }
}
