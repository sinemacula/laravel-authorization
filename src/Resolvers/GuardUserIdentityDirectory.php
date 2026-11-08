<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Support\IdentityPrincipals;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The default identity directory: complete only where the package can know the
 * answer.
 *
 * Under the shipped subject resolver, `AuthGuardSubjectResolver`, every subject
 * is the user Laravel authenticated and is its own identity, so an identity
 * owns no principal but itself and its list is complete and empty. Under any
 * other resolver, the application decides which principals an identity owns,
 * and the package cannot know them, so the list is incomplete and the grant
 * scope query answers `unknown` unless a grant already proves the identity
 * reaches outside the tenant. Nothing is inferred from the identity's model.
 *
 * The bound subject resolver is read on every call, so a resolver bound after
 * the directory was built is honoured.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GuardUserIdentityDirectory implements IdentityDirectory
{
    /**
     * Create a new identity directory.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the bound subject resolver is read from. */
        private Container $container,
    ) {}

    /**
     * Return no principals beyond the identity, completely, under the shipped
     * subject resolver; otherwise an incomplete list naming none.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $identity
     * @return \SineMacula\Laravel\Authorization\Support\IdentityPrincipals
     */
    #[\Override]
    public function principalsOf(Reference $identity): IdentityPrincipals
    {
        $resolver = $this->container->make(SubjectResolver::class);

        return $resolver instanceof AuthGuardSubjectResolver ? IdentityPrincipals::complete() : IdentityPrincipals::incomplete();
    }
}
