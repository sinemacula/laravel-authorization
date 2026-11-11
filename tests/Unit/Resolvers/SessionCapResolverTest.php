<?php

declare(strict_types = 1);

namespace Tests\Unit\Resolvers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Resolvers\SessionCapResolver;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\CredentialScopes;
use SineMacula\Laravel\Authorization\Support\SessionScopes;
use Tests\Feature\Stubs\CredentialScopesSource;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubSessionPolicySource;

/**
 * Unit tests for the resolver of a check's session caps.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(SessionCapResolver::class)]
final class SessionCapResolverTest extends TestCase
{
    /**
     * The credential's scopes are mapped to their patterns through the scope
     * map, a scope it does not map naming itself, and come before the explicit
     * caps; the source is asked once, about the subject.
     *
     * @return void
     */
    public function testTheCredentialsScopesAreMappedAndComeFirst(): void
    {
        $user     = new \stdClass;
        $subject  = new Subject($user, $user);
        $source   = new StubSessionPolicySource(['editor', 'users:read']);
        $resolver = new SessionCapResolver($source, new SessionScopes(['editor' => ['posts:*']]));

        self::assertSame([['credential', ['posts:*', 'users:read']], ['capped[1]', ['posts:read']]], $resolver->capsFor($subject, [['posts:read']])->caps);
        self::assertSame([$subject], $source->calls);
    }

    /**
     * A credential with no cap adds none, so only the explicit caps cap a
     * person's check, and with none of those nothing does; an empty one is
     * kept.
     *
     * @return void
     */
    public function testACredentialWithoutACapAddsNone(): void
    {
        $user     = new \stdClass;
        $resolver = new SessionCapResolver(new StubSessionPolicySource);

        self::assertSame([], $resolver->capsFor(new Subject($user, $user))->caps);
        self::assertSame([['capped[1]', ['posts:read']]], $resolver->capsFor(new Subject($user, $user), [['posts:read']])->caps);
        self::assertSame([['credential', []]], (new SessionCapResolver(new StubSessionPolicySource([])))->capsFor(new Subject($user, $user))->caps);
    }

    /**
     * A source reading the subject's own scopes is given them unchanged, so a
     * subject carrying scopes is capped by their patterns, one carrying none by
     * an empty cap, and one carrying no cap by nothing.
     *
     * @return void
     */
    public function testTheSubjectsOwnScopesReachTheSource(): void
    {
        $user     = new \stdClass;
        $resolver = new SessionCapResolver(new CredentialScopesSource, new SessionScopes(['editor' => ['posts:*']]));

        self::assertSame([['credential', ['posts:*', 'users:read']]], $resolver->capsFor(new Subject($user, $user, scopes: CredentialScopes::of(['editor', 'users:read'])))->caps);
        self::assertSame([['credential', []]], $resolver->capsFor(new Subject($user, $user, scopes: CredentialScopes::of([])))->caps);
        self::assertSame([], $resolver->capsFor(new Subject($user, $user))->caps);
    }

    /**
     * A machine whose credential carries no cap is capped by an empty one, the
     * default resolver's included, whatever explicit caps are given; one whose
     * credential carries scopes is capped by them.
     *
     * @return void
     */
    public function testAMachineWithoutCredentialScopesIsAllowedNothing(): void
    {
        $machine = new StubMachine;
        $subject = new Subject($machine, $machine);

        self::assertSame([['credential:missing', []]], (new SessionCapResolver)->capsFor($subject)->caps);
        self::assertSame([['credential:missing', []], ['capped[1]', ['*']]], (new SessionCapResolver)->capsFor($subject, [['*']])->caps);
        self::assertSame([['credential', ['posts:read']]], (new SessionCapResolver(new StubSessionPolicySource(['posts:read'])))->capsFor($subject)->caps);
    }
}
