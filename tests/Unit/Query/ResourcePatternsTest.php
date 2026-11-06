<?php

declare(strict_types = 1);

namespace Tests\Unit\Query;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\ResourcePatterns;

/**
 * Unit tests for telling whether a resolved resource pattern covers every
 * record of a type.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResourcePatterns::class)]
final class ResourcePatternsTest extends TestCase
{
    /**
     * Return each pattern, as `fnmatch()` reads it, with whether it covers
     * every record of `posts`.
     *
     * @return iterable<string, array{string, bool}>
     */
    public static function patterns(): iterable
    {
        yield 'every resource' => ['*', true];
        yield 'the type' => ['posts:*', true];
        yield 'a prefix of the type' => ['po*', true];
        yield 'the type without its colon' => ['posts*', true];
        yield 'an escaped prefix of the type' => ['p\osts:*', true];
        yield 'another type' => ['comments:*', false];
        yield 'a disjoint prefix' => ['x*', false];
        yield 'a record of another type' => ['comments:5', false];
        yield 'a literal shorter than the type' => ['pos', false];
        yield 'an escaped literal of another type' => ['comm\ents:5', false];
        yield 'the type alone' => ['posts', false];
        yield 'a record of the type' => ['posts:5', false];
        yield 'minus zero' => ['posts:-0', false];
        yield 'the type with an empty key' => ['posts:', false];
        yield 'the literal star key' => ['posts:\*', false];
        yield 'a longer prefix' => ['posts:4*', false];
        yield 'a backslash prefix' => ['posts:\\\*', false];
        yield 'a question mark' => ['posts:?', false];
        yield 'a bracket' => ['posts:[0-9]', false];
        yield 'two stars' => ['**', false];
        yield 'a star in the middle' => ['p*s:*', false];
        yield 'a trailing lone backslash' => ['posts\\', false];
        yield 'a question mark of another type' => ['comments:?', false];
    }

    /**
     * A pattern compiles exactly when it covers every record of the type,
     * whatever the record's key.
     *
     * @param  string  $pattern
     * @param  bool  $isWhole
     * @return void
     */
    #[DataProvider('patterns')]
    public function testAPatternNamesTheRecordsAlikeOnlyWhenNoKeyCanMatter(string $pattern, bool $isWhole): void
    {
        self::assertSame($isWhole, ResourcePatterns::coversEveryRecord($pattern, 'posts'));
    }

    /**
     * A namespaced class's morph type, its backslashes escaped as a pattern
     * holds them, is matched by its own prefix.
     *
     * @return void
     */
    public function testAnEscapedClassNameIsItsOwnPrefix(): void
    {
        self::assertTrue(ResourcePatterns::coversEveryRecord('App\\\Models\\\Post:*', 'App\Models\Post'));
        self::assertTrue(ResourcePatterns::coversEveryRecord('App\\\Mod*', 'App\Models\Post'));
        self::assertFalse(ResourcePatterns::coversEveryRecord('App\\\Models\\\Post:\\\*', 'App\Models\Post'));
    }

    /**
     * A pattern of `PHP_MAXPATHLEN` bytes or more, which `fnmatch()` refuses,
     * does not cover the records; one a byte shorter can.
     *
     * @return void
     */
    public function testAPatternTooLongForFnmatchIsRefused(): void
    {
        $type = \str_repeat('x', \PHP_MAXPATHLEN);

        self::assertFalse(ResourcePatterns::coversEveryRecord(\str_repeat('x', \PHP_MAXPATHLEN - 1) . '*', $type));
        self::assertTrue(ResourcePatterns::coversEveryRecord(\str_repeat('x', \PHP_MAXPATHLEN - 2) . '*', $type));
    }
}
