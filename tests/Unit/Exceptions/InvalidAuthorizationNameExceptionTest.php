<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Concerns\ValidatesAuthorizationName;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationNameException;
use Tests\Unit\Exceptions\Stubs\StubAuthorizationEntity;

/**
 * Unit tests for `InvalidAuthorizationNameException` and the
 * `ValidatesAuthorizationName` trait's default kind fallback.
 *
 * The exception is thrown by the name mutator shared by the Role, Permission,
 * and Policy models; the constructor, `getKind()`, and `getName()` accessors
 * are part of the SemVer-stable API surface and are consumed by the demo app's
 * error handler to render human-readable validation messages.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidAuthorizationNameException::class)]
#[CoversTrait(ValidatesAuthorizationName::class)]
final class InvalidAuthorizationNameExceptionTest extends TestCase
{
    /** @var string Malformed name carrying the whitespace the validator rejects. */
    private const string HAS_SPACE = 'has space';

    /**
     * The constructor formats a stable message that identifies both the entity
     * kind and the offending name, and exposes both through typed accessors.
     *
     * @return void
     */
    public function testConstructsMessageAndExposesAccessors(): void
    {
        $exception = new InvalidAuthorizationNameException('role', self::HAS_SPACE);

        self::assertSame('role', $exception->getKind());
        self::assertSame(self::HAS_SPACE, $exception->getName());
        self::assertStringContainsString('Invalid role name \'' . self::HAS_SPACE . '\'', $exception->getMessage());
        self::assertSame(422, $exception->getCode());
    }

    /**
     * Consumers that use the trait without overriding the kind resolver fall
     * back to the generic `authorization entity` label.
     *
     * @return void
     */
    public function testDefaultKindFallback(): void
    {
        $entity = new StubAuthorizationEntity;

        self::assertSame('authorization entity', $entity->resolveKind());
    }

    /**
     * The trait's name mutator raises the typed exception with the default kind
     * label when the consumer has not overridden it.
     *
     * @return void
     */
    public function testMutatorRaisesWithDefaultKindWhenNotOverridden(): void
    {
        $entity = new StubAuthorizationEntity;

        try {
            $entity->setNameAttribute(self::HAS_SPACE);
            self::fail('Expected InvalidAuthorizationNameException.');
        } catch (InvalidAuthorizationNameException $exception) {
            self::assertSame('authorization entity', $exception->getKind());
            self::assertSame(self::HAS_SPACE, $exception->getName());
        }
    }

    /**
     * Non-string inputs are reported as empty-string names so the error message
     * remains parseable.
     *
     * @return void
     */
    public function testNonStringInputIsReportedAsEmpty(): void
    {
        $entity = new StubAuthorizationEntity;

        try {
            $entity->setNameAttribute(123);
            self::fail('Expected InvalidAuthorizationNameException.');
        } catch (InvalidAuthorizationNameException $exception) {
            self::assertSame('', $exception->getName());
        }
    }
}
