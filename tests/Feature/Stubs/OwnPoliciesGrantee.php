<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Models\Policy as PolicyModel;

/**
 * Test grantee model that implements the policy contract itself, without the
 * package's traits, so its policies come from its own code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OwnPoliciesGrantee extends Model implements SupportsPolicies // @phpstan-ignore-line
{
    /** @var bool Disable auto-incrementing - stubs use explicit IDs. */
    public $incrementing = false;

    /** @var string Primary key type. */
    protected $keyType = 'string';

    /** @var list<string> Mass-assignable attributes. */
    protected $fillable = ['id', 'name'];

    /** @var string|null Backing table. */
    protected $table = 'stub_identities';

    /**
     * Attach nothing: the grantee's policies are fixed.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    #[\Override]
    public function attachPolicy(PolicyModel $policy): static
    {
        return $this;
    }

    /**
     * Detach nothing: the grantee's policies are fixed.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return static
     */
    #[\Override]
    public function detachPolicy(PolicyModel $policy): static
    {
        return $this;
    }

    /**
     * Sync nothing: the grantee's policies are fixed.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Policy>  $policies
     * @return static
     */
    #[\Override]
    public function syncPolicies(array $policies): static
    {
        return $this;
    }

    /**
     * Return the policy the grantee's own code gives.
     *
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    #[\Override]
    public function getPolicies(): array
    {
        return [Policy::fromArray(['name' => 'own', 'statements' => [['effect' => 'allow', 'actions' => ['reports:read']]]])];
    }
}
