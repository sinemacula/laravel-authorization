<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;

/**
 * The default session policy source (AUTHZ-13.3). It knows no credential, so it
 * answers from what the subject says its credential carries (N126): null for
 * `CredentialScopes::uncapped()` and the scopes for `CredentialScopes::of()`,
 * and null, no cap, when the subject says nothing, whatever session or guard it
 * names. Failing closed for a credential it cannot establish is the duty of a
 * source that knows credentials (see `SessionPolicySource`). Without a resolver
 * filling the scopes, a person's checks are capped only by what the caller
 * passes to `Authorization::capped()`, and a machine principal, which needs its
 * credential's scopes, is allowed nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoSessionPolicy implements SessionPolicySource
{
    /**
     * Answer the scopes the subject says its credential carries, or null when
     * it carries no cap or the subject says nothing.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     */
    #[\Override]
    public function scopesFor(Subject $subject): ?array
    {
        return $subject->scopes?->scopes();
    }
}
