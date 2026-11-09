<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Evaluation\Policy;

/**
 * Test identity whose grants come from its own code rather than the package's
 * grant tables: its permissions and its policies are fixed by the model, so no
 * grant row says where they came from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CustomGrantsIdentity extends Model implements AuthorizableIdentity
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
     * Return the permissions the model grants itself.
     *
     * @return array<int, string>
     */
    #[\Override]
    public function getPermissions(): array
    {
        return ['reports:read'];
    }

    /**
     * Return the policies the model attaches to itself.
     *
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    #[\Override]
    public function getPolicies(): array
    {
        return [Policy::fromArray(['name' => 'coded', 'statements' => [['effect' => 'allow', 'actions' => ['reports:export']]]])];
    }
}
