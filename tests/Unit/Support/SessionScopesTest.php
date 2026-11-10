<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Support\SessionScopes;

/**
 * Unit tests for the scope map.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(SessionScopes::class)]
final class SessionScopesTest extends TestCase
{
    /**
     * A mapped scope names its patterns, and every other scope, with no map at
     * all included, names itself as an action or an action pattern.
     *
     * @return void
     */
    public function testAScopeNamesItsPatternsOrItself(): void
    {
        $scopes = new SessionScopes(['editor' => ['posts:*', 'comments:read']]);

        self::assertSame(['posts:*', 'comments:read'], $scopes->patternsFor(['editor']));
        self::assertSame(['posts:read', 'users:*'], $scopes->patternsFor(['posts:read', 'users:*']));
        self::assertSame(['posts:read'], (new SessionScopes)->patternsFor(['posts:read']));
        self::assertSame([], $scopes->patternsFor([]));
    }

    /**
     * The patterns of several scopes are given in the order of the scopes, each
     * pattern once.
     *
     * @return void
     */
    public function testThePatternsOfSeveralScopesAreEachGivenOnce(): void
    {
        $scopes = new SessionScopes(['editor' => ['posts:*', 'comments:read'], 'reader' => ['comments:read', 'posts:read']]);

        self::assertSame(['comments:read', 'posts:read', 'posts:*'], $scopes->patternsFor(['reader', 'editor']));
        self::assertSame(['posts:read'], $scopes->patternsFor(['posts:read', 'posts:read']));
    }

    /**
     * The configuration maps a scope to its patterns, or lists it on its own to
     * name itself, and an entry of any other shape, or a list holding an entry
     * that is not a pattern, is refused rather than skipped.
     *
     * @return void
     */
    public function testFromConfigReadsMappedAndListedScopes(): void
    {
        $scopes = SessionScopes::fromConfig([
            'editor' => ['posts:*', 'comments:read'],
            'posts:read',
            'reader' => ['posts:read'],
        ]);

        self::assertSame(['editor', 'posts:read', 'reader'], $scopes->names());
        self::assertSame(['posts:*', 'comments:read'], $scopes->patternsFor(['editor']));
        self::assertSame(['posts:read'], $scopes->patternsFor(['posts:read']));
        self::assertSame(['posts:read'], $scopes->patternsFor(['reader']));
        self::assertFalse($scopes->isMapped('broken'));
        self::assertSame(['broken'], $scopes->patternsFor(['broken']));

        foreach ([['editor' => ['posts:*', 42]], ['broken' => 'posts:edit'], [7], ['editor' => []], ['']] as $map) {
            self::assertRefused($map);
        }
    }

    /**
     * A configuration that is not an array is refused, never read as mapping no
     * scope.
     *
     * @return void
     */
    public function testFromConfigOfANonArrayIsRefused(): void
    {
        self::assertSame([], SessionScopes::fromConfig([])->names());

        self::assertRefused(null);
        self::assertRefused('editor');
    }

    /**
     * The map names the scopes it maps, in order, and no other; a scope listed
     * on its own whose name is numeric is named as a string, and keeps naming
     * itself.
     *
     * @return void
     */
    public function testTheMapNamesTheScopesItMaps(): void
    {
        $scopes = SessionScopes::fromConfig(['editor' => ['posts:*'], '7']);

        self::assertTrue($scopes->isMapped('editor'));
        self::assertTrue($scopes->isMapped('7'));
        self::assertFalse($scopes->isMapped('reader'));
        self::assertSame(['editor', '7'], $scopes->names());
        self::assertSame(['7'], $scopes->patternsFor(['7']));
    }

    /**
     * Assert the scope map is refused under `authorization.session.scopes`.
     *
     * @param  mixed  $map
     * @return void
     */
    private static function assertRefused(mixed $map): void
    {
        try {
            SessionScopes::fromConfig($map);

            self::fail('The scope map ' . \var_export($map, true) . ' was not refused.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.session.scopes', $exception->getConfigKey());
        }
    }
}
