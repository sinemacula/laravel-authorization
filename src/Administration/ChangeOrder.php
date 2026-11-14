<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

/**
 * The order a batch of delegated changes is decided in (see
 * `ActingContext::authorizeIn()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ChangeOrder
{
    /**
     * Return the changes in the order a batch decides them: kind by kind, in
     * the order their actions first appear, and within a kind by where each
     * holds and what it acts on.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Administration\OperationResource>  $changes
     * @return list<\SineMacula\Laravel\Authorization\Administration\OperationResource>
     */
    public static function of(array $changes): array
    {
        $kinds = \array_flip(\array_unique(\array_map(static fn (OperationResource $change): string => $change->action, $changes)));

        $order = static fn (OperationResource $change): array => [$kinds[$change->action], self::placeOf($change)];

        \usort($changes, static fn (OperationResource $one, OperationResource $other): int => $order($one) <=> $order($other));

        return $changes;
    }

    /**
     * Return where the change holds and what it acts on, as one string: its
     * tenant, its application and its record's type and key.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $change
     * @return string
     */
    private static function placeOf(OperationResource $change): string
    {
        $target = $change->change?->target;

        return \serialize([$change->tenant, $change->change?->scope->application, $target?->getMorphClass(), $target?->getKey()]);
    }
}
