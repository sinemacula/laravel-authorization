<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * A grantee with an auto-incrementing integer key that soft-deletes.
 *
 * @property int $id
 * @property string|null $name
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NumberedIdentity extends Model implements AuthorizableIdentity
{
    use HasAuthorization, SoftDeletes;

    /** @var list<string> Mass-assignable attributes. */
    protected $fillable = ['name'];

    /** @var string|null Backing table. */
    protected $table = 'stub_numbered_identities';
}
