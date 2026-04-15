<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\Authorizable as AuthorizableContract;
use SineMacula\Laravel\Authorization\Traits\Authorizable;

/**
 * Second stub model used to exercise polymorphic pivots with two
 * distinct authorizable shapes in the same schema.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
class StubSecondAuthorizable extends Model implements AuthorizableContract
{
    use Authorizable;

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
     * Disable auto-incrementing — stubs use explicit IDs.
     *
     * @var bool
     */
    public $incrementing = false;

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
    protected $table = 'stub_second_authorizables';
}
