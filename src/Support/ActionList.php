<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;

/**
 * The actions a check over several actions decides (AUTHZ-9.5): the manager's
 * `any()` and `all()`.
 *
 * The actions are decided one at a time, in the order given, and the walk stops
 * at the first decision that settles the answer: `any()` at the first allow,
 * `all()` at the first refusal, so no action after it is decided. A list that
 * names no action is refused before anything is decided, since it would neither
 * allow nor refuse anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ActionList
{
    /**
     * Create a new action list instance.
     *
     * @param  non-empty-array<int, string>  $actions
     */
    private function __construct(

        /** The actions to decide, in the order given. */
        private array $actions,
    ) {}

    /**
     * Return the list of the supplied actions, refusing an empty one.
     *
     * @param  string  $method
     * @param  array<int, string>  $actions
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public static function of(string $method, array $actions): self
    {
        if ($actions === []) {
            throw InvalidCheckArgumentException::noActions($method);
        }

        return new self($actions);
    }

    /**
     * Determine whether the callback allows any action, deciding none after the
     * first it allows.
     *
     * @param  \Closure(string): bool  $isAllowed
     * @return bool
     */
    public function isAnyAllowed(\Closure $isAllowed): bool
    {
        return $this->settles($isAllowed, true);
    }

    /**
     * Determine whether the callback allows every action, deciding none after
     * the first it refuses.
     *
     * @param  \Closure(string): bool  $isAllowed
     * @return bool
     */
    public function isEveryAllowed(\Closure $isAllowed): bool
    {
        return !$this->settles($isAllowed, false);
    }

    /**
     * Determine whether a decision of the callback gives the supplied outcome,
     * deciding the actions in order and none after the first that gives it.
     *
     * @param  \Closure(string): bool  $isAllowed
     * @param  bool  $outcome
     * @return bool
     */
    private function settles(\Closure $isAllowed, bool $outcome): bool
    {
        foreach ($this->actions as $action) {
            if ($isAllowed($action) === $outcome) {
                return true;
            }
        }

        return false;
    }
}
