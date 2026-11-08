<?php

declare(strict_types = 1);

namespace Tests\Feature\Hooks;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Exceptions\GrantRefusedException;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Fixtures\GrantHooks\RecordingGrantHook;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for the ordered composite of grant hooks, the default binding
 * of the grant hook contract (AUTHZ-11.3).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantHooks::class)]
final class GrantHooksTest extends TestCase
{
    /**
     * The hooks run in order, and the first that throws stops the rest.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheHooksRunInOrderAndStopAtTheFirstThatThrows(): void
    {
        /** @var \ArrayObject<int, string> $order */
        $order = new \ArrayObject;

        $first  = new RecordingGrantHook(static fn () => $order->append('first'));
        $second = new RecordingGrantHook(static fn () => $order->append('second'));
        $last   = new RecordingGrantHook(static fn () => $order->append('last'));

        (new GrantHooks([$first, $second]))->beforeWidening(self::widening());

        self::assertSame(['first', 'second'], $order->getArrayCopy());

        $refusing = new RefusingGrantHook;

        try {
            (new GrantHooks([$first, $refusing, $last]))->beforeWidening(self::widening());

            self::fail('The widening was not refused.');
        } catch (GrantRefusedException) {
            self::assertSame(1, $refusing->refused);
        }

        self::assertSame(['first', 'second', 'first'], $order->getArrayCopy());
        self::assertSame([], $last->widenings);
    }

    /**
     * A composite holding no hook is empty and does nothing; one holding a hook
     * is not, and returns its hooks in order.
     *
     * @return void
     */
    public function testAnEmptyCompositeDoesNothing(): void
    {
        $empty = new GrantHooks;
        $hook  = new RecordingGrantHook;

        $empty->beforeWidening(self::widening());

        self::assertTrue($empty->isEmpty());
        self::assertSame([], $empty->hooks());
        self::assertFalse((new GrantHooks([$hook]))->isEmpty());
        self::assertSame([$hook], (new GrantHooks([$hook]))->hooks());
    }

    /**
     * The composite is built from the configured classes, in order, each from
     * the container, and is the default binding of the contract: empty with
     * nothing configured.
     *
     * @return void
     */
    public function testTheCompositeIsBuiltFromTheConfiguredClasses(): void
    {
        $recording = new RecordingGrantHook;
        $refusing  = new RefusingGrantHook;

        $this->app?->instance(RecordingGrantHook::class, $recording);
        $this->app?->instance(RefusingGrantHook::class, $refusing);

        $default = $this->app?->make(GrantHook::class);

        self::assertInstanceOf(GrantHooks::class, $default);
        self::assertTrue($default->isEmpty());

        config(['authorization.grant_hooks' => [RefusingGrantHook::class, RecordingGrantHook::class]]);

        $configured = GrantHooks::fromConfig($this->app ?? self::fail('No application.'));

        self::assertSame([$refusing, $recording], $configured->hooks());
    }

    /**
     * Return a widening of no grants.
     *
     * @return \SineMacula\Laravel\Authorization\Hooks\GrantWidening
     */
    private static function widening(): GrantWidening
    {
        $identity = new Reference('identities', '1');

        return new GrantWidening('operation', true, null, null, null, $identity, $identity, [], new \DateTimeImmutable);
    }
}
