<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Concerns\HasAuthorization;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableGrantee;

/**
 * Test grantee whose policies come from its own code, while its permissions and
 * roles are the package's own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CodedPoliciesGrantee extends Model implements AuthorizableGrantee // @phpstan-ignore-line
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
    protected $table = 'stub_grantees';

    /**
     * Return no policies, whatever is attached.
     *
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    #[\Override]
    public function getPolicies(): array
    {
        return [];
    }
}
