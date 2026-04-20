<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Traits\HasAuthorization;

/**
 * Minimal Eloquent model used by feature tests to verify role, permission, and
 * policy assignment through the shipped traits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Fillable('id', 'name')]
#[Table(name: 'stub_identities', keyType: 'string', incrementing: false)]
class StubIdentity extends Model implements AuthorizableIdentity
{
    use HasAuthorization;
}
