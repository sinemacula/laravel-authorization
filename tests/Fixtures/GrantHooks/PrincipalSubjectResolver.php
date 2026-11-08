<?php

declare(strict_types = 1);

namespace Tests\Fixtures\GrantHooks;

use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Feature\Stubs\StubSecondIdentity;

/**
 * A subject resolver for an application with principals: a second stub identity
 * is a principal, whose identity the test maps by its key, and any other model
 * is its own identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PrincipalSubjectResolver implements SubjectResolver
{
    /**
     * Create a new resolver.
     *
     * @param  array<string, object|null>  $identities
     */
    public function __construct(

        /** The identity of each principal, by the principal's key. */
        private array $identities = [],
    ) {}

    /**
     * Resolve no subject: the tests name theirs.
     *
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    #[\Override]
    public function resolve(): ?Subject
    {
        return null;
    }

    /**
     * Make the user a subject: a principal with its mapped identity, or any
     * other model as its own identity.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        if (!$user instanceof StubSecondIdentity) {
            return new Subject($user, $user);
        }

        /** @var string $key */
        $key = $user->getKey();

        return new Subject($user, $this->identities[$key] ?? null);
    }
}
