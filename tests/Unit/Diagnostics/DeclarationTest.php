<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding;
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
     * A declaration stands while the closure it names is bound, by identity,
     * and supplies the contract, has an instance over it once an instance
     * handed to the container supplies the contract instead, is overridden once
     * another closure is bound, and is unverified when it names none.
     *
     * @return void
     */
    public function testItStandsOnlyWhileItsClosureSuppliesTheContract(): void
    {
        $binding     = static fn (): object => new \stdClass;
        $lookalike   = static fn (): object => new \stdClass;
        $declaration = new Declaration('Contract', 'acme/sibling', ['Adapter'], null, Lifetime::SCOPED, $binding);
        $built       = new \stdClass;

        self::assertSame('standing', $declaration->standing(new CurrentBinding($binding, null, Lifetime::SCOPED, null, null, false)));
        self::assertSame('standing', $declaration->standing(new CurrentBinding($binding, $built, Lifetime::SCOPED, null, null, true)));
        self::assertSame('instance_over_it', $declaration->standing(new CurrentBinding($binding, new \ArrayObject, Lifetime::INSTANCE, null, null, false)));
        self::assertSame('overridden', $declaration->standing(new CurrentBinding($lookalike, null, Lifetime::SCOPED, null, null, false)));
        self::assertSame('overridden', $declaration->standing(new CurrentBinding(null, new \ArrayObject, Lifetime::INSTANCE, null, null, false)));
        $unproven = new Declaration('Contract', 'acme/sibling', ['Adapter'], null, Lifetime::SCOPED, null);

        self::assertSame('unverified', $unproven->standing(new CurrentBinding($binding, null, null, null, null, false)));
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
