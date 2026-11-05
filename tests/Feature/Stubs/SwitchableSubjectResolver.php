<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Subject resolver whose tenant a test sets per simulated request or job, the
 * way a real resolver reads the tenant from the request or the job's payload.
 *
 * The subject is a placeholder: the tests that use it care about the tenant the
 * scope reads, not about who the checks are for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SwitchableSubjectResolver implements SubjectResolver
{
    /** @var object|null The tenant every resolver instance returns until changed. */
    public static ?object $tenant = null;

    /**
     * Resolve a placeholder subject in the tenant currently set on the class.
     *
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function resolve(): Subject
    {
        return $this->forUser(new \stdClass);
    }

    /**
     * Make the given user the subject, in the tenant currently set on the
     * class.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    #[\Override]
    public function forUser(object $user): Subject
    {
        return new Subject($user, $user, self::$tenant);
    }
}
