<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Compares the references an event carries with the records they name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ComparesReferences
{
    /**
     * Determine whether the reference names the record: the same morph type and
     * key.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $reference
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $record
     * @return bool
     */
    protected static function refersTo(?Reference $reference, Model|Reference $record): bool
    {
        $expected = Reference::of($record);

        return $reference?->type === $expected->type && $reference->id === $expected->id;
    }

    /**
     * Return the `type:id` form of each reference, for comparing lists.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $references
     * @return list<string>
     */
    protected static function keysOf(array $references): array
    {
        return \array_map(static fn (Reference $reference): string => $reference->type . ':' . $reference->id, $references);
    }
}
