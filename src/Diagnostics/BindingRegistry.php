<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use Illuminate\Contracts\Container\Container;

/**
 * The record of every seam the package bound, taken as it registered (see
 * `SeamRecord`), held in the container the package registered in.
 *
 * It is held as an instance of that container, never statically, so each
 * application keeps its own. A container cloned from it, as an Octane sandbox
 * is, shares the records, which describe what the package bound as it
 * registered and never change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BindingRegistry
{
    /** @var array<string, \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord> Each record, keyed by its contract. */
    private array $records = [];

    /**
     * Return the registry the container holds, holding a new one first when it
     * holds none.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return self
     */
    public static function of(Container $container): self
    {
        $registry = ContainerState::instance($container, self::class);

        if ($registry instanceof self) {
            return $registry;
        }

        $registry = new self;

        $container->instance(self::class, $registry);

        return $registry;
    }

    /**
     * Keep the record of a seam, in place of an earlier record of its contract
     * when the package registers again.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord  $record
     * @return void
     */
    public function record(SeamRecord $record): void
    {
        $this->records[$record->contract] = $record;
    }

    /**
     * Return the record of the contract, or null when the package bound none.
     *
     * @param  string  $contract
     * @return \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord|null
     */
    public function get(string $contract): ?SeamRecord
    {
        return $this->records[$contract] ?? null;
    }

    /**
     * Return every record, keyed by its contract, in the order the package
     * bound them.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Diagnostics\SeamRecord>
     */
    public function all(): array
    {
        return $this->records;
    }
}
