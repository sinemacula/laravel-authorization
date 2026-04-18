<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Traits\HasAuthorization;

/**
 * Minimal Eloquent model used by feature tests to verify role, permission, and
 * policy assignment through the shipped traits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
class StubIdentity extends Model implements AuthorizableIdentity
{
    use HasAuthorization;

    /** @var bool Disable auto-incrementing — stubs use explicit IDs. */
    public $incrementing = false;

    /** @var string Primary key column. */
    protected $primaryKey = 'id';

    /** @var string Primary key type. */
    protected $keyType = 'string';

    /** @var list<string> Mass-assignable attributes. */
    protected $fillable = ['id', 'name'];

    /** @var string|null Backing table. */
    protected $table = 'stub_identities';
}
