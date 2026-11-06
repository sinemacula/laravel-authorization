<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A session policy source that answers every subject with the scopes given, or
 * null for no cap, recording each subject it is asked about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubSessionPolicySource implements SessionPolicySource
{
    /** @var list<\SineMacula\Laravel\Authorization\Subject> Each subject asked about. */
    public array $calls = [];

    /**
     * Create a new source answering with the scopes given.
     *
     * @param  list<string>|null  $scopes
     */
    public function __construct(

        /** The scopes every credential carries, or null for no cap. */
        private readonly ?array $scopes = null,
    ) {}

    /**
     * Answer the fixed scopes, recording the subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     */
    #[\Override]
    public function scopesFor(Subject $subject): ?array
    {
        $this->calls[] = $subject;

        return $this->scopes;
    }
}
