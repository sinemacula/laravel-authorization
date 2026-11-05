<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Auth\Authenticatable as AuthenticatableConcern;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * An identity Laravel can sign in that eager-loads its roles, so loading it
 * queries a tenant-scoped model while the subject is being resolved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EagerRolesIdentity extends Model implements Authenticatable, AuthorizableIdentity
{
    use AuthenticatableConcern, HasAuthorization;

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

    /** @var list<string> Relations loaded with every query. */
    protected $with = ['roles'];
}
