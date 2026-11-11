<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A session policy source that knows credentials, recording each subject it is
 * asked about. It answers from the scopes the subject carries when it says what
 * they are; otherwise from the credential the subject names, its session or a
 * guard whose caller is the subject's own model, failing closed with an empty
 * list for one it does not know; and null for a subject naming no credential.
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
     * Create a source knowing the credentials given.
     *
     * @param  array<string, list<string>|null>  $credentials
     */
    public function __construct(

        /** The scopes of each credential known, keyed `session:{id}` or `guard:{name}`, null for one with no cap. */
        private readonly array $credentials = [],
    ) {}

    /**
     * Answer the scopes the subject says its credential carries, or those of
     * the credential it names, recording the subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return list<string>|null
     */
    #[\Override]
    public function scopesFor(Subject $subject): ?array
    {
        $this->calls[] = $subject;

        if ($subject->scopes !== null) {
            return $subject->scopes->scopes();
        }

        $credential = $this->credentialOf($subject);

        return $credential === null ? null : $this->scopesOf($credential);
    }

    /**
     * Return the credential the subject names: its session, or its guard when
     * the guard's caller is the subject's own model, or null for neither.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return string|null
     */
    private function credentialOf(Subject $subject): ?string
    {
        if ($subject->session !== null) {
            return 'session:' . $subject->session;
        }

        return $subject->guard !== null && self::isCaller(Auth::guard($subject->guard)->user(), $subject->subject) ? 'guard:' . $subject->guard : null;
    }

    /**
     * Return the scopes of the credential, or an empty list, allowing nothing,
     * for one the source does not know.
     *
     * @param  string  $credential
     * @return list<string>|null
     */
    private function scopesOf(string $credential): ?array
    {
        return \array_key_exists($credential, $this->credentials) ? $this->credentials[$credential] : [];
    }

    /**
     * Determine whether the guard's caller is the model: the same instance, or
     * a model with the same key.
     *
     * @param  object|null  $caller
     * @param  object  $model
     * @return bool
     */
    private static function isCaller(?object $caller, object $model): bool
    {
        return $caller === $model || ($caller instanceof Model && $model instanceof Model && $caller->is($model));
    }
}
