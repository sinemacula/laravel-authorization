<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableGrantee;

/**
 * Test stub - identity that does not declare the hook, so the trait falls back
 * to `config('authorization.defaults.guard')`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DefaultGuardUser extends Model implements AuthorizableGrantee // @phpstan-ignore-line
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
    protected $table = 'stub_grantees'; // @phpstan-ignore property.phpDocType
}
