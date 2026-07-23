<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * Test stub - identity declaring `api` as its authorization guard via the
 * duck-typed hook.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApiGuardedUser extends Model implements AuthorizableIdentity
{
    use HasAuthorization;

    /** @var bool */
    public $incrementing = false;

    /** @var string */
    protected $primaryKey = 'id';

    /** @var string */
    protected $keyType = 'string';

    /** @var array<int, string> */
    protected $fillable = ['id']; // @phpstan-ignore property.phpDocType

    /** @var string */
    protected $table = 'api_guarded_users'; // @phpstan-ignore property.phpDocType

    /**
     * The guard name used for name-based authorization lookups.
     *
     * @return string
     */
    public function getAuthorizationGuard(): string
    {
        return 'api';
    }
}
