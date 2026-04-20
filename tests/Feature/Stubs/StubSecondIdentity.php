<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Traits\HasAuthorization;

/**
 * Second stub model used to exercise polymorphic pivots with two distinct
 * authorizable shapes in the same schema.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Fillable('id', 'name')]
#[Table(name: 'stub_second_identities', keyType: 'string', incrementing: false)]
class StubSecondIdentity extends Model implements AuthorizableIdentity
{
    use HasAuthorization;
}
