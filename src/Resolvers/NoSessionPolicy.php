<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;

/**
 * The default session policy source: no credential carries a cap (AUTHZ-13.3),
 * so a person's checks are capped only by what the caller passes to
 * `Authorization::capped()`, and a machine principal, which needs its
 * credential's scopes, is allowed nothing until the application binds a source.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoSessionPolicy implements SessionPolicySource
{
    /**
     * Answer that the subject's credential carries no cap.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     */
    #[\Override]
    public function scopesFor(Subject $subject): ?array
    {
        return null;
    }
}
