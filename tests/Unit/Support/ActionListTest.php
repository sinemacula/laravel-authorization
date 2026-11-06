<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Support\ActionList;

/**
 * Unit tests for `ActionList`, which walks the actions of a check over several
 * actions in order and stops at the first decision that settles the answer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActionList::class)]
final class ActionListTest extends TestCase
{
    /**
     * An empty list is refused, naming the method it was given to.
     *
     * @return void
     */
    public function testAnEmptyListIsRefused(): void
    {
        $this->expectException(InvalidCheckArgumentException::class);
        $this->expectExceptionMessage('any() takes at least one action to decide, none given.');

        ActionList::of('any', []);
    }

    /**
     * Any is allowed at the first allow, deciding no action after it.
     *
     * @return void
     */
    public function testAnyStopsAtTheFirstAllow(): void
    {
        $decided = [];
        $list    = ActionList::of('any', ['a', 'b', 'c']);

        self::assertTrue($list->isAnyAllowed(self::allowing(['b'], $decided)));
        self::assertSame(['a', 'b'], $decided);
    }

    /**
     * Any is refused when no action is allowed, every action decided in order.
     *
     * @return void
     */
    public function testAnyIsRefusedWhenNothingIsAllowed(): void
    {
        $decided = [];

        self::assertFalse(ActionList::of('any', ['a', 'b', 'c'])->isAnyAllowed(self::allowing([], $decided)));
        self::assertSame(['a', 'b', 'c'], $decided);
    }

    /**
     * Every is refused at the first refusal, deciding no action after it.
     *
     * @return void
     */
    public function testEveryStopsAtTheFirstRefusal(): void
    {
        $decided = [];

        self::assertFalse(ActionList::of('all', ['a', 'b', 'c'])->isEveryAllowed(self::allowing(['a', 'c'], $decided)));
        self::assertSame(['a', 'b'], $decided);
    }

    /**
     * Every is allowed when each action is allowed, every action decided in
     * order.
     *
     * @return void
     */
    public function testEveryIsAllowedWhenEachIsAllowed(): void
    {
        $decided = [];

        self::assertTrue(ActionList::of('all', ['a', 'b', 'c'])->isEveryAllowed(self::allowing(['a', 'b', 'c'], $decided)));
        self::assertSame(['a', 'b', 'c'], $decided);
    }

    /**
     * The actions are decided in the order given, whatever their keys.
     *
     * @return void
     */
    public function testTheActionsAreDecidedInTheOrderGiven(): void
    {
        $decided = [];

        self::assertTrue(ActionList::of('all', [5 => 'c', 1 => 'a'])->isEveryAllowed(self::allowing(['a', 'c'], $decided)));
        self::assertSame(['c', 'a'], $decided);
    }

    /**
     * Return a callback allowing the supplied actions alone and recording each
     * action it decides.
     *
     * @param  list<string>  $allowed
     * @param  list<string>  $decided
     * @return \Closure(string): bool
     */
    private static function allowing(array $allowed, array &$decided): \Closure
    {
        return static function (string $action) use ($allowed, &$decided): bool {
            $decided[] = $action;

            return \in_array($action, $allowed, true);
        };
    }
}
