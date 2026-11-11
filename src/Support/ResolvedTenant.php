<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * The tenant of the subject the bound `SubjectResolver` returned for the
 * current request or job, together with the resolver it came from.
 *
 * The service provider binds this holder with `scoped()`, so it is built once
 * per request or job from the resolver and discarded at its end: Laravel's
 * queue worker forgets scoped instances before each job, and Octane runs each
 * request on a fresh sandbox. `TenantScope` reads the tenant from here instead
 * of keeping its own memo, so no tenant outlives the request or job that
 * resolved it. When the resolver bound now is not the one the holder came from,
 * the scope builds a new holder, so the next query sees a rebound resolver.
 *
 * The tenant is null when there is no subject or the subject has no tenant, and
 * only platform-wide rows are visible then. The subject's application is held
 * with it: grants made for one application count only on that application, and
 * with none, only grants for every application count. The tenant's ancestors,
 * read through the bound tenant tree, are held with it once read. A holder put
 * in place to decide just below its tenant (see `TenantScope::within()`) reads
 * a chain standing there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ResolvedTenant
{
    /** @var array{0: \SineMacula\Laravel\Authorization\Contracts\TenantTree, 1: \SineMacula\Laravel\Authorization\Support\TenantChain}|null The chain read for the tenant, with the tree it was read through. */
    private ?array $chain = null;

    /**
     * Create a new resolved-tenant holder.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SubjectResolver  $resolver
     * @param  object|null  $tenant
     * @param  string|null  $application
     * @param  string|null  $guard
     * @param  bool  $isBelow
     */
    public function __construct(

        /** The resolver the tenant was read from. */
        public readonly SubjectResolver $resolver,

        /** The resolved tenant, or null when no tenant is active. */
        public readonly ?object $tenant,

        /** The application the subject is on, or null for none. */
        public readonly ?string $application = null,

        /** The default authentication guard when the subject was resolved. */
        public readonly ?string $guard = null,

        /** Whether checks are decided just below the tenant, counting a grant made there only when it reaches below. */
        public readonly bool $isBelow = false,
    ) {}

    /**
     * Resolve the subject's tenant and application through the given resolver,
     * refusing, before the resolver is asked, while the package of the current
     * application refuses (see `PackageState`): the holder is built for what
     * reads it, which refuses itself until the package is healthy, so a context
     * source handed it as the configuration is validated is still built.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SubjectResolver  $resolver
     * @param  string|null  $guard
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function from(SubjectResolver $resolver, ?string $guard = null): self
    {
        PackageState::guardBuild(Container::getInstance());

        $subject = $resolver->resolve();

        return new self($resolver, $subject?->tenant, $subject?->application, $guard);
    }

    /**
     * Determine whether the tenant was read from the given resolver under the
     * given default guard. The default resolver names the application after the
     * default guard, which Laravel's `auth:` middleware changes during a
     * request, so a holder read under another guard is read again.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SubjectResolver  $resolver
     * @param  string|null  $guard
     * @return bool
     */
    public function isFrom(SubjectResolver $resolver, ?string $guard = null): bool
    {
        return $this->resolver === $resolver && $this->guard === $guard;
    }

    /**
     * Return the tenant and its ancestors through the given tree, read once for
     * the request or job, and again when another tree is bound.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     * @return \SineMacula\Laravel\Authorization\Support\TenantChain
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public function chain(TenantTree $tree): TenantChain
    {
        if ($this->chain === null || $this->chain[0] !== $tree) {
            $this->chain = [$tree, $this->read($tree, false)];
        }

        return $this->chain[1];
    }

    /**
     * Read the tenant's ancestors again through the given tree, in place of the
     * chain held, and of the answer a batch of checks keeps, and return the
     * chain read.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     * @return \SineMacula\Laravel\Authorization\Support\TenantChain
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public function refreshChain(TenantTree $tree): TenantChain
    {
        $this->chain = [$tree, $this->read($tree, true)];

        return $this->chain[1];
    }

    /**
     * Read the tenant's chain through the given tree, afresh when asked, past
     * the answers a batch of checks keeps (see `TenantChain::of()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     * @param  bool  $isFresh
     * @return \SineMacula\Laravel\Authorization\Support\TenantChain
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    private function read(TenantTree $tree, bool $isFresh): TenantChain
    {
        $tenant = $this->tenant === null ? null : new Reference(...TenantScope::extractTenantPair($this->tenant));

        return TenantChain::of($tenant, $tree, $this->isBelow, $isFresh);
    }
}
