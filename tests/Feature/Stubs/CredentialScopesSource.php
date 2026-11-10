<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A session policy source answering the scopes the subject itself carries, as
 * its subject resolver filled them, recording each subject it is asked about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CredentialScopesSource implements SessionPolicySource
{
    /** @var list<\SineMacula\Laravel\Authorization\Subject> Each subject asked about. */
    public array $calls = [];

    /**
     * Answer the subject's own scopes, recording the subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     */
    #[\Override]
    public function scopesFor(Subject $subject): ?array
    {
        $this->calls[] = $subject;

        return $subject->scopes;
    }
}
