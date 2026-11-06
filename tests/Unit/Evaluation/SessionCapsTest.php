<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;

/**
 * Unit tests for the session caps of a check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(SessionCaps::class)]
final class SessionCapsTest extends TestCase
{
    /**
     * No caps at all is the default, and a credential without a cap and no
     * explicit cap make none.
     *
     * @return void
     */
    public function testNoCredentialCapAndNoExplicitCapMakeNone(): void
    {
        self::assertSame([], (new SessionCaps)->caps);
        self::assertSame([], SessionCaps::of(null)->caps);
        self::assertSame([], SessionCaps::of(null, [])->caps);
    }

    /**
     * The credential's cap comes first, named `credential`, then each explicit
     * cap, outermost first, named by its position from 1; an empty credential
     * cap is kept, since it allows nothing.
     *
     * @return void
     */
    public function testTheCredentialCapComesFirstThenEachExplicitCap(): void
    {
        self::assertSame(
            [['credential', ['posts:*']], ['capped[1]', ['posts:read']], ['capped[2]', []]],
            SessionCaps::of(['posts:*'], [['posts:read'], []])->caps,
        );
        self::assertSame([['credential', []]], SessionCaps::of([])->caps);
        self::assertSame([['capped[1]', ['posts:read']]], SessionCaps::of(null, [['posts:read']])->caps);
    }

    /**
     * A machine whose credential carries no cap gets an empty cap in its place,
     * whatever explicit caps are given, and one whose credential carries a cap
     * keeps it.
     *
     * @return void
     */
    public function testAMachineWithoutCredentialScopesGetsAnEmptyCap(): void
    {
        self::assertSame([['credential:missing', []]], SessionCaps::of(null, [], true)->caps);
        self::assertSame([['credential:missing', []], ['capped[1]', ['*']]], SessionCaps::of(null, [['*']], true)->caps);
        self::assertSame([['credential', ['posts:read']]], SessionCaps::of(['posts:read'], [], true)->caps);
        self::assertSame('credential', SessionCaps::CREDENTIAL);
        self::assertSame('credential:missing', SessionCaps::MISSING_CREDENTIAL);
        self::assertSame('capped', SessionCaps::EXPLICIT);
    }

    /**
     * A pattern covers an action it equals or matches with `fnmatch`, with no
     * escapes, and an empty list covers nothing.
     *
     * @return void
     */
    public function testPatternsCoverByEqualityOrMatch(): void
    {
        self::assertTrue(SessionCaps::covers(['posts:read'], 'posts:read'));
        self::assertTrue(SessionCaps::covers(['comments:*', 'posts:*'], 'posts:edit'));
        self::assertTrue(SessionCaps::covers(['*'], 'anything'));
        self::assertTrue(SessionCaps::covers(['posts\[1]'], 'posts\[1]'));
        self::assertTrue(SessionCaps::covers(['a\*'], 'a\b'));
        self::assertFalse(SessionCaps::covers(['posts:read'], 'posts:edit'));
        self::assertFalse(SessionCaps::covers(['posts:*'], 'comments:read'));
        self::assertFalse(SessionCaps::covers([], 'posts:read'));
    }
}
