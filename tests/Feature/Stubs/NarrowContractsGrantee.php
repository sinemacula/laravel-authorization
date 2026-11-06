<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;

/**
 * A grantee that holds roles, permissions and policies through the standalone
 * traits, implementing each narrow contract but not `AuthorizableIdentity`, so
 * the boundaries set on it are shown to cap it all the same.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-ignore sineMaculaLaravel.modelBehaviour, sineMaculaLaravel.modelBehaviour, sineMaculaLaravel.modelBehaviour, sineMaculaLaravel.modelBehaviour
 */
final class NarrowContractsGrantee extends Model implements SupportsPermissions, SupportsPolicies, SupportsRoles // @phpstan-ignore sineMaculaLaravel.modelBehaviour
{
    use HasPermissions, HasPolicies, HasRoles;

    /** @var bool Disable auto-incrementing — stubs use explicit IDs. */
    public $incrementing = false;

    /** @var string Primary key type. */
    protected $keyType = 'string';

    /** @var list<string> Mass-assignable attributes. */
    protected $fillable = ['id', 'name'];

    /** @var string|null Backing table. */
    protected $table = 'stub_identities';
}
