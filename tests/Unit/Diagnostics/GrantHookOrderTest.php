<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin;
use SineMacula\Laravel\Authorization\Diagnostics\GrantHookOrder;
use SineMacula\Laravel\Authorization\Diagnostics\SeamRow;

/**
 * Unit tests for the order the grant hooks run in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantHookOrder::class)]
final class GrantHookOrderTest extends TestCase
{
    /**
     * The hooks listed run first, in order, each by its class name or, when the
     * entry is not one, by its type alone; the bound hook runs last.
     *
     * @return void
     */
    public function testTheListedHooksRunBeforeTheBoundHook(): void
    {
        $hooks = GrantHookOrder::of(['App\FirstHook', 'not a class name'], self::bound(Origin::LATER_BINDING, ['App\BoundHook']));

        self::assertSame([
            [1, 'configured', 'App\FirstHook', 'string', true],
            [2, 'configured', null, 'string', true],
            [3, 'bound', 'App\BoundHook', null, true],
        ], \array_map(static fn (array $hook): array => [$hook['position'], $hook['source'], $hook['class'], $hook['type'], $hook['runs']], $hooks));
        self::assertSame('later_binding', $hooks[2]['origin']);
    }

    /**
     * A value that lists no hooks lists none, and the package's default, which
     * holds no hook, runs none.
     *
     * @return void
     */
    public function testThePackageDefaultRunsNoHook(): void
    {
        $hooks = GrantHookOrder::of('not a list', self::bound(Origin::PACKAGE_DEFAULT, ['Default']));

        self::assertCount(1, $hooks);
        self::assertFalse($hooks[0]['runs']);
        self::assertFalse(GrantHookOrder::of([], self::bound(Origin::UNBOUND, []))[0]['runs']);
    }

    /**
     * Return the row of the bound hook.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin  $origin
     * @param  list<string>  $classes
     * @return \SineMacula\Laravel\Authorization\Diagnostics\SeamRow
     */
    private static function bound(Origin $origin, array $classes): SeamRow
    {
        return new SeamRow('GrantHook', $origin, $classes, null, null, [], new CurrentBinding(null, null, null, null, null, false), null, null);
    }
}
