<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\HeldPermissions;

/**
 * Unit tests for matching an asked action against the permissions held, by the
 * wildcard rules, naming the one that covers it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(HeldPermissions::class)]
final class HeldPermissionsTest extends TestCase
{
    /**
     * The action itself, when held, is the match, whatever patterns cover it
     * too and wherever it sits in the list.
     *
     * @return void
     */
    public function testTheActionItselfIsMatchedBeforeAnyPattern(): void
    {
        self::assertSame('posts:edit', HeldPermissions::match(['*', 'posts:*', 'posts:edit'], 'posts:edit'));
        self::assertSame('posts:edit', HeldPermissions::match(['posts:edit', '*'], 'posts:edit'));
    }

    /**
     * Failing the action itself, the first covering pattern in byte order is
     * the match, whatever order the names were read in.
     *
     * @return void
     */
    public function testTheFirstCoveringPatternInByteOrderIsMatched(): void
    {
        self::assertSame('*', HeldPermissions::match(['posts:*', 'users:read', '*'], 'posts:edit'));
        self::assertSame('*', HeldPermissions::match(['*', 'posts:*'], 'posts:edit'));
        self::assertSame('posts:*', HeldPermissions::match(['posts:e*', 'posts:*'], 'posts:edit'));
        self::assertSame('*:edit', HeldPermissions::match(['posts:*', '*:edit'], 'posts:edit'));
        self::assertSame('1*0*', HeldPermissions::match(['9*', '10*', '1*0*'], '100'));
    }

    /**
     * Held names that do not cover the asked action: none, another action, a
     * pattern of another prefix, another case, an asked pattern that only a
     * wider held one would cover, and a backslash taken literally.
     *
     * @return iterable<string, array{list<string>, string}>
     */
    public static function uncovered(): iterable
    {
        yield 'none held' => [[], 'posts:edit'];
        yield 'another action' => [['posts:read'], 'posts:edit'];
        yield 'another prefix' => [['users:*'], 'posts:edit'];
        yield 'another case' => [['Posts:edit', 'POSTS:*'], 'posts:edit'];
        yield 'a literal asked pattern' => [['posts:edit'], 'posts:*'];
        yield 'a literal backslash' => [['posts\*'], 'posts*'];
    }

    /**
     * No held name that covers the action, none at all included, matches
     * nothing.
     *
     * @param  list<string>  $held
     * @param  string  $action
     * @return void
     */
    #[DataProvider('uncovered')]
    public function testANameThatDoesNotCoverTheActionMatchesNothing(array $held, string $action): void
    {
        self::assertNull(HeldPermissions::match($held, $action));
    }
}
