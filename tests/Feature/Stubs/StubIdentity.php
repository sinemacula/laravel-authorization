<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Traits\HasAuthorization;

/**
 * Minimal Eloquent model used by feature tests to verify role,
 * permission, and policy assignment through the shipped traits.
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

    /**
     * Disable auto-incrementing — stubs use explicit IDs.
     *
     * @var bool
     */
    public $incrementing = false;

    /**
     * Primary key column.
     *
     * @var string
     */
    protected $primaryKey = 'id';

    /**
     * Primary key type.
     *
     * @var string
     */
    protected $keyType = 'string';

    /**
     * Mass-assignable attributes.
     *
     * @var list<string>
     */
    protected $fillable = ['id', 'name'];

    /**
     * Backing table.
     *
     * @var string|null
     */
    protected $table = 'stub_identities';
}
