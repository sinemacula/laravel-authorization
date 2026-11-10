<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * Test identity whose permissions can never be read, as a remote permission
 * service that is down would leave them, while its policies are the package's
 * own, so a check that asks for its permissions fails and one that never needs
 * them does not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailingPermissionsIdentity extends Model implements AuthorizableIdentity
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
    protected $table = 'stub_identities';

    /**
     * Refuse to say which permissions the model holds.
     *
     * @return array<int, string>
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function getPermissions(): array
    {
        throw new \RuntimeException('The permission service is down.');
    }
}
