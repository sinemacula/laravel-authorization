<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine;

/**
 * A machine principal: a grantee like any other, marked as a machine, on the
 * second stub identity table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubMachine extends Model implements AuthorizableIdentity, AuthorizableMachine
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
    protected $table = 'stub_second_identities';
}
