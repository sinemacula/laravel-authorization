<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * Test stub - identity that does not declare the hook, so the trait falls back
 * to `config('authorization.defaults.guard')`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DefaultGuardUser extends Model implements AuthorizableIdentity
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
    protected $table = 'stub_identities'; // @phpstan-ignore property.phpDocType
}
