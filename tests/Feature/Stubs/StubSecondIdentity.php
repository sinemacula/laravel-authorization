<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Traits\HasAuthorization;

/**
 * Second stub model used to exercise polymorphic pivots with two
 * distinct authorizable shapes in the same schema.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
class StubSecondIdentity extends Model implements AuthorizableIdentity
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
     * @var string
     */
    protected $table = 'stub_second_identities';
}
