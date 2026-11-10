<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding;
use SineMacula\Laravel\Authorization\Diagnostics\Declaration;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Lifetime;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin;
use SineMacula\Laravel\Authorization\Diagnostics\SeamRecord;
use SineMacula\Laravel\Authorization\Diagnostics\SeamRow;

/**
 * Unit tests for one seam as the configuration report shows it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamRow::class)]
final class SeamRowTest extends TestCase
{
    /**
     * One known class is the class; a factory's set never is, and neither is
     * none; a closure with no class known is decided at first use.
     *
     * @return void
     */
    public function testTheClassIsOneKnownClassAlone(): void
    {
        $factory = new Declaration('C', 'owner', ['A', 'B'], 'per request', Lifetime::TRANSIENT, null);
        $single  = new Declaration('C', 'owner', ['A'], 'per request', Lifetime::TRANSIENT, null);

        self::assertSame('A', self::row(['A'])->class());
        self::assertNull(self::row(['A', 'B'], declaration: $factory)->class());
        self::assertNull(self::row(['A'], declaration: $single)->class());
        self::assertNull(self::row([])->class());
        self::assertTrue(self::row([], 'file.php:3')->isDecidedAtFirstUse());
        self::assertFalse(self::row(['A'])->isDecidedAtFirstUse());
        self::assertFalse(self::row([])->isDecidedAtFirstUse());
    }

    /**
     * The row's shape names the history, the configuration key, the deferred
     * provider loaded at registration and the declaration's state.
     *
     * @return void
     */
    public function testTheShapeIsVersioned(): void
    {
        $binding     = static fn (): mixed => null;
        $record      = new SeamRecord('C', $binding, 'authorization.default:C', 'A', 'authorization.c', true, null, null, 'Acme\Provider');
        $declaration = new Declaration('C', 'acme/sibling', ['B'], null, Lifetime::SCOPED, $binding);
        $row         = new SeamRow(
            'C',
            Origin::CONFIGURED,
            ['A'],
            null,
            Lifetime::SCOPED,
            ['authorization.grant_hooks'],
            new CurrentBinding($binding, null, Lifetime::TRANSIENT, null, null, true),
            $record,
            $declaration,
        );

        self::assertSame([
            'contract'            => 'C',
            'origin'              => 'configured',
            'class'               => 'A',
            'classes'             => ['A'],
            'decides'             => null,
            'factory'             => null,
            'lifetime'            => 'scoped',
            'extenders'           => ['authorization.grant_hooks'],
            'config_key'          => 'authorization.c',
            'alias'               => null,
            'deferred_provider'   => 'Acme\Provider',
            'previously_resolved' => true,
            'declaration'         => ['owner' => 'acme/sibling', 'classes' => ['B'], 'decides' => null, 'lifetime' => 'scoped', 'state' => 'standing'],
        ], $row->toArray());
    }

    /**
     * Return a row of the classes given, unbound otherwise.
     *
     * @param  list<string>  $classes
     * @param  string|null  $factory
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Declaration|null  $declaration
     * @return \SineMacula\Laravel\Authorization\Diagnostics\SeamRow
     */
    private static function row(array $classes, ?string $factory = null, ?Declaration $declaration = null): SeamRow
    {
        return new SeamRow('C', Origin::LATER_BINDING, $classes, $factory, null, [], new CurrentBinding(null, null, null, null, null, false), null, $declaration);
    }
}
