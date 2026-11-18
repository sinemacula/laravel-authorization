<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Foundation\Auth\User;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableGrantee;

/**
 * A user model as the README writes one, on Laravel's own base user class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FoundationUser extends User implements AuthorizableGrantee
{
    use HasAuthorization;

    /** @var list<string> Mass-assignable attributes. */
    protected $fillable = ['name'];

    /** @var string|null Backing table. */
    protected $table = 'stub_numbered_grantees';
}
