<?php

declare(strict_types = 1);

namespace Tests\Unit\Query;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Query\KeyTarget;
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
     * Return each pattern, as `fnmatch()` reads it, with the records of `posts`
     * it names: every one, none, the key exactly, or the start of the key (with
     * whether the key exactly the start is left out); null for one that cannot
     * be compared with a key.
     *
     * @return iterable<string, array{string, array{string, string, bool}|null}>
     */
    public static function patterns(): iterable
    {
        yield 'every resource' => ['*', [KeyTarget::ALL, '', false]];
        yield 'the type' => ['posts:*', [KeyTarget::ALL, '', false]];
        yield 'a prefix of the type' => ['po*', [KeyTarget::ALL, '', false]];
        yield 'the type without its colon' => ['posts*', [KeyTarget::ALL, '', false]];
        yield 'an escaped prefix of the type' => ['p\osts:*', [KeyTarget::ALL, '', false]];
        yield 'another type' => ['comments:*', [KeyTarget::NONE, '', false]];
        yield 'a disjoint prefix' => ['x*', [KeyTarget::NONE, '', false]];
        yield 'a record of another type' => ['comments:5', [KeyTarget::NONE, '', false]];
        yield 'a literal shorter than the type' => ['pos', [KeyTarget::NONE, '', false]];
        yield 'the type alone' => ['posts', [KeyTarget::NONE, '', false]];
        yield 'a record of the type' => ['posts:5', [KeyTarget::EQUALS, '5', false]];
        yield 'an escaped record of the type' => ['posts:a\b', [KeyTarget::EQUALS, 'ab', false]];
        yield 'minus zero, compared as text' => ['posts:-0', [KeyTarget::EQUALS, '-0', false]];
        yield 'the type with an empty key' => ['posts:', [KeyTarget::NONE, '', false]];
        yield 'the literal star key' => ['posts:\*', [KeyTarget::NONE, '', false]];
        yield 'a key ending as a type' => ['posts:x:\*', [KeyTarget::NONE, '', false]];
        yield 'a longer prefix' => ['posts:4*', [KeyTarget::PREFIX, '4', false]];
        yield 'a prefix ending as a type' => ['posts:x:\**', [KeyTarget::PREFIX, 'x:*', true]];
        yield 'a prefix that is the star key' => ['posts:\**', [KeyTarget::PREFIX, '*', true]];
        yield 'a backslash prefix' => ['posts:\\\*', [KeyTarget::PREFIX, '\\', false]];
        yield 'a question mark' => ['posts:?', null];
        yield 'a bracket' => ['posts:[0-9]', null];
        yield 'two stars' => ['**', null];
        yield 'a star in the middle' => ['p*s:*', null];
        yield 'a trailing lone backslash' => ['posts\\', null];
        yield 'a question mark of another type' => ['comments:?', null];
    }

    /**
     * A pattern names the records `fnmatch()` would match its identifier
     * against, decided on the whole identifier, or is refused.
     *
     * @param  string  $pattern
     * @param  array{string, string, bool}|null  $expected
     * @return void
     */
    #[DataProvider('patterns')]
    public function testAPatternNamesTheRecordsFnmatchMatches(string $pattern, ?array $expected): void
    {
        $target = ResourcePatterns::targetOf($pattern, 'posts');

        self::assertSame($expected, $target === null ? null : [$target->kind, $target->value, $target->isValueExcluded]);
    }

    /**
     * What a pattern names agrees with `Statement::covers()` on every edge key:
     * a record is named exactly when `fnmatch()` matches its identifier, and,
     * for one ending in `:*`, the identifier less its last byte too.
     *
     * @return void
     */
    public function testATargetAgreesWithFnmatchOnTheWholeIdentifier(): void
    {
        $keys     = ['5', '*', 'x:*', 'x:', 'ab', 'a', '\\', '-0', '0'];
        $patterns = ['posts:5', 'posts:\*', 'posts:x:\*', 'posts:x:*', 'posts:x:\**', 'posts:\**', 'posts:a*', 'posts:\\\*', 'posts:-0', '*', 'p*'];

        foreach ($patterns as $pattern) {
            $target = ResourcePatterns::targetOf($pattern, 'posts');

            self::assertNotNull($target);

            foreach ($keys as $key) {
                $identifier = 'posts:' . $key;
                $isCovered  = \fnmatch($pattern, $identifier) && (!\str_ends_with($identifier, ':*') || \fnmatch($pattern, \substr($identifier, 0, -1)));

                self::assertSame($isCovered, self::isNamed($target, $key), "{$pattern} on {$key}");
            }
        }
    }

    /**
     * A namespaced class's morph type, its backslashes escaped as a resolved
     * pattern holds them, is matched by its own prefix.
     *
     * @return void
     */
    public function testAnEscapedClassNameIsItsOwnPrefix(): void
    {
        self::assertTrue(ResourcePatterns::targetOf('App\\\Models\\\Post:*', 'App\Models\Post')?->isAll());
        self::assertTrue(ResourcePatterns::targetOf('App\\\Mod*', 'App\Models\Post')?->isAll());
        self::assertTrue(ResourcePatterns::targetOf('App\\\Models\\\Post:\*', 'App\Models\Post')?->isNone());
    }

    /**
     * A pattern of `PHP_MAXPATHLEN` bytes or more, which `fnmatch()` refuses,
     * is refused; one a byte shorter is not.
     *
     * @return void
     */
    public function testAPatternTooLongForFnmatchIsRefused(): void
    {
        $type = \str_repeat('x', \PHP_MAXPATHLEN);

        self::assertNull(ResourcePatterns::targetOf(\str_repeat('x', \PHP_MAXPATHLEN - 1) . '*', $type));
        self::assertTrue(ResourcePatterns::targetOf(\str_repeat('x', \PHP_MAXPATHLEN - 2) . '*', $type)?->isAll());
    }

    /**
     * Determine whether the target names the record of the key.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\KeyTarget  $target
     * @param  string  $key
     * @return bool
     */
    private static function isNamed(KeyTarget $target, string $key): bool
    {
        return match ($target->kind) {
            KeyTarget::ALL    => true,
            KeyTarget::NONE   => false,
            KeyTarget::EQUALS => $key === $target->value,
            default           => \str_starts_with($key, $target->value) && !($target->isValueExcluded && $key === $target->value),
        };
    }
}
