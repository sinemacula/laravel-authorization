<?php

declare(strict_types = 1);

namespace Tests\Integration\Administration;

use Random\Engine\Mt19937;
use Random\Randomizer;

/**
 * The random choices of one seeded scenario, each drawn from the seed in the
 * order it is asked, so the same seed makes the same choices.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SeededChoices
{
    /** @var \Random\Randomizer The source of the choices. */
    private Randomizer $random;

    /**
     * Create the choices of the seed.
     *
     * @param  int  $seed
     */
    public function __construct(int $seed)
    {
        $this->random = new Randomizer(new Mt19937($seed));
    }

    /**
     * Return a whole number between the bounds, both included.
     *
     * @param  int  $min
     * @param  int  $max
     * @return int
     */
    public function between(int $min, int $max): int
    {
        return $this->random->getInt($min, $max);
    }

    /**
     * Determine, at random, whether a chance of one in the given number comes
     * up.
     *
     * @param  int  $in
     * @return bool
     */
    public function isOneIn(int $in): bool
    {
        return $this->random->getInt(1, $in) === 1;
    }

    /**
     * Return one of the items, at random.
     *
     * @template TItem
     *
     * @param  list<TItem>  $items
     * @return TItem
     *
     * @throws \LogicException
     */
    public function pick(array $items): mixed
    {
        if ($items === []) {
            throw new \LogicException('There is nothing to pick from.');
        }

        return $items[$this->random->getInt(0, \count($items) - 1)];
    }

    /**
     * Return up to the given number of distinct items, at random.
     *
     * @template TItem
     *
     * @param  list<TItem>  $items
     * @param  int  $most
     * @return list<TItem>
     */
    public function some(array $items, int $most): array
    {
        $picked = [];

        for ($count = $this->random->getInt(0, $most); $count > 0 && $items !== []; $count--) {
            $key      = $this->random->getInt(0, \count($items) - 1);
            $picked[] = $items[$key];

            \array_splice($items, $key, 1);
        }

        return $picked;
    }
}
