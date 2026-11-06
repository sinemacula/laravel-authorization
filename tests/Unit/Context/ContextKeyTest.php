<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Context\ContextKey;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;

/**
 * Unit tests for `ContextKey`, one declared context key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextKey::class)]
final class ContextKeyTest extends TestCase
{
    /**
     * A key holds its path, type and testability, and may be tested unless
     * declared otherwise.
     *
     * @return void
     */
    public function testHoldsItsDeclaration(): void
    {
        $key = new ContextKey('request.ip', ContextKeyType::IP);

        self::assertSame('request.ip', $key->path);
        self::assertSame(ContextKeyType::IP, $key->type);
        self::assertTrue($key->isTestable);
        self::assertFalse((new ContextKey('authentication.level', ContextKeyType::NUMBER, false))->isTestable);
    }

    /**
     * A key's namespace is the first segment of its path.
     *
     * @return void
     */
    public function testItsNamespaceIsTheFirstSegment(): void
    {
        self::assertSame('request', (new ContextKey('request.ip', ContextKeyType::IP))->namespace());
        self::assertSame('input', (new ContextKey('input.post.status', ContextKeyType::STRING))->namespace());
        self::assertSame('flag', (new ContextKey('flag', ContextKeyType::BOOL))->namespace());
    }

    /**
     * Any dot path's namespace is its first segment, the whole path when it has
     * only one, and empty when the path starts with a dot or is empty.
     *
     * @return void
     */
    public function testAPathsNamespaceIsItsFirstSegment(): void
    {
        self::assertSame('input', ContextKey::namespaceOf('input.post.status'));
        self::assertSame('principal', ContextKey::namespaceOf('principal'));
        self::assertSame('0', ContextKey::namespaceOf('0.x'));
        self::assertSame('', ContextKey::namespaceOf('.a'));
        self::assertSame('', ContextKey::namespaceOf(''));
    }
}
