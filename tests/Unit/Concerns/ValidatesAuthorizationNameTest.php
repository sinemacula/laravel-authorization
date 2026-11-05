<?php

declare(strict_types = 1);

namespace Tests\Unit\Concerns;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Concerns\ValidatesAuthorizationName;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationNameException;
use Tests\Unit\Exceptions\Stubs\StubAuthorizationEntity;

/**
 * Unit tests for the `ValidatesAuthorizationName` trait.
 *
 * Role and permission names are letters, digits and `_ - : . *`, with `*` as
 * the only wildcard. The static predicate is the single rule shared by the
 * attribute mutator and the writers that bypass it, so both are pinned here.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ValidatesAuthorizationName::class)]
final class ValidatesAuthorizationNameTest extends TestCase
{
    /**
     * Names the rule accepts.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function validNames(): iterable
    {
        yield 'letters' => ['admin'];
        yield 'mixed-case' => ['PlatformAdmin'];
        yield 'digits' => ['42'];
        yield 'underscore' => ['a_b'];
        yield 'hyphen' => ['platform-admin'];
        yield 'colon' => ['posts:edit'];
        yield 'dot' => ['posts.edit'];
        yield 'nested-dots' => ['sso.connection.trust'];
        yield 'dotted-wildcard' => ['posts.*'];
        yield 'colon-wildcard' => ['posts:*'];
        yield 'leading-wildcard' => ['*:read'];
        yield 'bare-wildcard' => ['*'];
        yield 'every-character' => ['aZ09_-:.*'];
        yield 'longest' => [\str_repeat('a', 191)];
    }

    /**
     * The predicate accepts every name made of the allowed characters.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('validNames')]
    public function testPredicateAcceptsValidName(string $name): void
    {
        self::assertTrue(StubAuthorizationEntity::isValidAuthorizationName($name));
    }

    /**
     * Values the rule refuses.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function invalidNames(): iterable
    {
        yield 'empty' => [''];
        yield 'too-long' => [\str_repeat('a', 192)];
        yield 'whitespace' => ['has space'];
        yield 'leading-whitespace' => [' posts.edit'];
        yield 'trailing-newline' => ["posts.edit\n"];
        yield 'question-mark' => ['posts.?'];
        yield 'opening-bracket' => ['posts.[a'];
        yield 'closing-bracket' => ['posts.a]'];
        yield 'brackets' => ['posts.[ab]'];
        yield 'braces' => ['posts.{a,b}'];
        yield 'backslash' => ['App\Models\Post'];
        yield 'forward-slash' => ['posts/edit'];
        yield 'integer' => [42];
        yield 'null' => [null];
    }

    /**
     * The predicate refuses empty names, non-strings, whitespace and every glob
     * metacharacter other than `*`.
     *
     * @param  mixed  $name
     * @return void
     */
    #[DataProvider('invalidNames')]
    public function testPredicateRefusesInvalidName(mixed $name): void
    {
        self::assertFalse(StubAuthorizationEntity::isValidAuthorizationName($name));
    }

    /**
     * The mutator stores a valid name unchanged.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('validNames')]
    public function testMutatorStoresValidName(string $name): void
    {
        $entity = new StubAuthorizationEntity;

        $entity->setNameAttribute($name);

        self::assertSame(['name' => $name], $entity->attributes);
    }

    /**
     * The mutator refuses an invalid name with the typed exception and leaves
     * the attributes untouched.
     *
     * @return void
     */
    public function testMutatorRefusesInvalidName(): void
    {
        $entity = new StubAuthorizationEntity;

        try {
            $entity->setNameAttribute('posts.?');
            self::fail('Expected InvalidAuthorizationNameException.');
        } catch (InvalidAuthorizationNameException $exception) {
            self::assertSame('authorization entity', $exception->getKind());
            self::assertSame('posts.?', $exception->getName());
        }

        self::assertSame([], $entity->attributes);
    }
}
