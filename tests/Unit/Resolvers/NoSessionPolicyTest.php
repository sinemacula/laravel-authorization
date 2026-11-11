<?php

declare(strict_types = 1);

namespace Tests\Unit\Resolvers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\CredentialScopes;

/**
 * Unit tests for the default session policy source, which knows no credential.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoSessionPolicy::class)]
final class NoSessionPolicyTest extends TestCase
{
    /**
     * A subject that says nothing of its credential's scopes is not capped,
     * even one in a session or on a guard, since the default source knows no
     * credential.
     *
     * @return void
     */
    public function testASubjectSayingNothingIsNotCapped(): void
    {
        $user = new \stdClass;

        self::assertNull((new NoSessionPolicy)->scopesFor(new Subject($user, $user, session: 'session-1')));
        self::assertNull((new NoSessionPolicy)->scopesFor(new Subject($user, $user, guard: 'web')));
    }

    /**
     * The scopes a subject says its credential carries are answered, an empty
     * list included, and a credential with no cap is answered as null.
     *
     * @return void
     */
    public function testAnswersTheScopesTheSubjectCarries(): void
    {
        $user   = new \stdClass;
        $source = new NoSessionPolicy;

        self::assertSame(['posts:read', 'posts:*'], $source->scopesFor(new Subject($user, $user, session: 'session-1', scopes: CredentialScopes::of(['posts:read', 'posts:*']))));
        self::assertSame([], $source->scopesFor(new Subject($user, $user, scopes: CredentialScopes::of([]))));
        self::assertNull($source->scopesFor(new Subject($user, $user, session: 'session-1', scopes: CredentialScopes::uncapped())));
    }
}
