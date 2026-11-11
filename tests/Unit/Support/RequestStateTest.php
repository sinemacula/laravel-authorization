<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Support\RequestState;

/**
 * Tests for forgetting the package's per-request state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequestState::class)]
final class RequestStateTest extends TestCase
{
    /**
     * Only the scoped instances held under the package's names are forgotten:
     * its class names, `authorization` and the `authorization.` keys. Another
     * package's scoped state, a scoped name that merely starts with the word,
     * and the package's own instances and singletons are kept.
     *
     * @return void
     */
    public function testOnlyThePackagesScopedStateIsForgotten(): void
    {
        $container = new Container;

        $container->scoped('other.first', static fn (): \stdClass => new \stdClass);
        $container->scoped(LastDecisionStore::class);
        $container->scoped('authorization', static fn (): \stdClass => new \stdClass);
        $container->scoped('authorization.default:Contract', static fn (): \stdClass => new \stdClass);
        $container->scoped('authorizations', static fn (): \stdClass => new \stdClass);
        $container->scoped('other.state', static fn (): \stdClass => new \stdClass);
        $container->singleton('SineMacula\Laravel\Authorization\Held', static fn (): \stdClass => new \stdClass);

        $held = [];

        foreach (['authorizations', 'other.state', 'SineMacula\Laravel\Authorization\Held'] as $abstract) {
            $held[$abstract] = $container->make($abstract);
        }

        $store   = $container->make(LastDecisionStore::class);
        $manager = $container->make('authorization');
        $default = $container->make('authorization.default:Contract');

        self::assertSame([LastDecisionStore::class, 'authorization', 'authorization.default:Contract'], RequestState::abstracts($container));

        RequestState::forget($container);

        self::assertNotSame($store, $container->make(LastDecisionStore::class));
        self::assertNotSame($manager, $container->make('authorization'));
        self::assertNotSame($default, $container->make('authorization.default:Contract'));

        foreach ($held as $abstract => $instance) {
            self::assertSame($instance, $container->make($abstract));
        }
    }

    /**
     * A container with no scoped state has nothing to forget.
     *
     * @return void
     */
    public function testAContainerWithNothingScopedForgetsNothing(): void
    {
        $container = new Container;

        RequestState::forget($container);

        self::assertSame([], RequestState::abstracts($container));
    }
}
