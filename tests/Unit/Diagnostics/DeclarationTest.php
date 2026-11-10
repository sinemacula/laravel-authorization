<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\Declaration;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;

/**
 * Unit tests for what a sibling package declared of a contract it binds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Declaration::class)]
final class DeclarationTest extends TestCase
{
    /**
     * A declaration stands while the closure it names is bound, by identity, is
     * overridden once another is, and is unverified when it names none.
     *
     * @return void
     */
    public function testItStandsOnlyWhileItsClosureIsBound(): void
    {
        $binding     = static fn (): object => new \stdClass;
        $lookalike   = static fn (): object => new \stdClass;
        $declaration = new Declaration('Contract', 'acme/sibling', ['Adapter'], null, Lifetime::SCOPED, $binding);

        self::assertSame('standing', $declaration->standing($binding));
        self::assertSame('overridden', $declaration->standing($lookalike));
        self::assertSame('overridden', $declaration->standing(null));
        self::assertSame('unverified', (new Declaration('Contract', 'acme/sibling', ['Adapter'], null, Lifetime::SCOPED, null))->standing($binding));
    }

    /**
     * A declaration that says when it decides is a factory; one that does not
     * is an adapter of one class.
     *
     * @return void
     */
    public function testAFactoryIsToldFromAnAdapter(): void
    {
        self::assertFalse((new Declaration('Contract', 'owner', ['A'], null, Lifetime::TRANSIENT, null))->isFactory());
        self::assertTrue((new Declaration('Contract', 'owner', ['A', 'B'], 'per request', Lifetime::TRANSIENT, null))->isFactory());
    }
}
