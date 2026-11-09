<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Reviews\Enums\ScopeSelection;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Which stored grants an access review reads, by tenant and by application,
 * each selection a value of its own rather than a null that could mean either
 * of two things:
 *
 * - `appliesIn()`: the grants that apply where a check is decided, in a tenant
 *   or at the platform, as the check reads them (see `TenantChain::grants()`):
 *   for a tenant, a platform-wide grant, the tenant's own and an ancestor's
 *   that reaches below it, never one made below the tenant; for the platform,
 *   the platform-wide grants alone. This is applicability, which runs the
 *   opposite way to the grant scope query's containment, so it never reuses it.
 *   Only the roles and permissions the tenant sees count (their owner the
 *   platform, the tenant or an ancestor), as a check there reads them;
 * - `rootedWithin()`: the grants made in a tenant or below it in the tree,
 *   wherever else they reach, never a platform-wide one;
 * - `everywhere()`: every stored grant, a cross-scope inventory.
 *
 * Each names its application explicitly (see `ApplicationSelector`), which
 * `appliesIn()` always takes and the others take as `any()` when none is given.
 *
 * A review is admitted in its reach (see `reach()` and `ReviewAdmission`): a
 * review applying in a tenant at that tenant; any other across all it covers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ReviewScope
{
    /**
     * Create a new review scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\ScopeSelection  $selection
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Reviews\ApplicationSelector  $application
     */
    private function __construct(

        /** How the grants are selected. */
        public ScopeSelection $selection,

        /** The tenant the grants apply in or are rooted within; null for the platform, and everywhere. */
        public ?Reference $tenant,

        /** The application the grants hold in. */
        public ApplicationSelector $application,
    ) {}

    /**
     * Return the selection of the grants that apply in the tenant, or at the
     * platform for none, in the application.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|\SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Reviews\ApplicationSelector  $application
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public static function appliesIn(AuthorizableTenant|Model|Reference|null $tenant, ApplicationSelector $application): self
    {
        return new self(ScopeSelection::APPLIES_IN, $tenant === null ? null : self::referenceTo($tenant), $application);
    }

    /**
     * Return the selection of the grants rooted at the tenant or below it, in
     * the application, or in any when none is given.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Reviews\ApplicationSelector|null  $application
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public static function rootedWithin(AuthorizableTenant|Model|Reference $tenant, ?ApplicationSelector $application = null): self
    {
        return new self(ScopeSelection::ROOTED_WITHIN, self::referenceTo($tenant), $application ?? ApplicationSelector::any());
    }

    /**
     * Return the selection of every stored grant, in the application, or in any
     * when none is given.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\ApplicationSelector|null  $application
     * @return self
     */
    public static function everywhere(?ApplicationSelector $application = null): self
    {
        return new self(ScopeSelection::EVERYWHERE, null, $application ?? ApplicationSelector::any());
    }

    /**
     * Return the reach the review is admitted across: one tenant's node for a
     * review applying in it; the tenant and every tenant below it for one
     * rooted within it; the platform, and so every tenant, for a review
     * applying at the platform or of everywhere. Its application is the one
     * named, or every application otherwise.
     *
     * @return \SineMacula\Laravel\Authorization\Support\GrantScope
     */
    public function reach(): GrantScope
    {
        $isNode = $this->selection === ScopeSelection::APPLIES_IN && $this->tenant !== null;

        return new GrantScope($this->tenant, $this->application->application, !$isNode);
    }

    /**
     * Return the reference to the tenant.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant|\SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    private static function referenceTo(AuthorizableTenant|Model|Reference $tenant): Reference
    {
        return $tenant instanceof Reference ? $tenant : new Reference(...TenantScope::extractTenantPair($tenant));
    }
}
