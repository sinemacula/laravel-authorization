<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;

/**
 * Compares the declared permission catalogue with the platform's permission
 * rows.
 *
 * The builder does no IO: the caller loads the rows, which must be the
 * platform's (tenant columns null), and passes the declared definitions. A
 * definition matches the row with the same name and guard, a null guard
 * matching a null one. Only the description and the category are compared; the
 * name and guard are the match itself, and the system flag and tenant columns
 * are never written by a sync.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionDiffBuilder
{
    /**
     * Build the diff between the declared definitions and the platform rows.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>  $definitions
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $rows
     * @return \SineMacula\Laravel\Authorization\Console\Support\PermissionDiff
     */
    public function build(array $definitions, array $rows): PermissionDiff
    {
        $rowsByKey = [];

        foreach ($rows as $row) {
            $rowsByKey[self::rowKey($row)] = $row;
        }

        $add = $update = $protected = $unchanged = [];

        foreach ($definitions as $definition) {
            $row = $rowsByKey[$definition->key()] ?? null;

            unset($rowsByKey[$definition->key()]);

            match (true) {
                $row === null                                               => $add[]       = $definition,
                $definition->hasMetadata($row->description, $row->category) => $unchanged[] = $row,
                $row->is_system                                             => $protected[] = $row,
                default                                                     => $update[]    = ['row' => $row, 'definition' => $definition],
            };
        }

        return new PermissionDiff(
            add: self::sortDefinitions($add),
            update: self::sortPairs($update),
            stale: self::sortRows(\array_filter($rowsByKey, static fn (Permission $row): bool => !$row->is_system)),
            protected: self::sortRows([...$protected, ...\array_filter($rowsByKey, static fn (Permission $row): bool => $row->is_system)]),
            unchanged: self::sortRows($unchanged),
        );
    }

    /**
     * Return the key of the row a permission row stands for.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $row
     * @return string
     */
    private static function rowKey(Permission $row): string
    {
        return PermissionDefinition::keyOf($row->name, $row->guard);
    }

    /**
     * Order definitions by name, then guard, guard-agnostic first.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>  $definitions
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     */
    private static function sortDefinitions(array $definitions): array
    {
        \usort($definitions, static fn (PermissionDefinition $left, PermissionDefinition $right): int => \strcmp($left->key(), $right->key()));

        return $definitions;
    }

    /**
     * Order row and definition pairs by name, then guard, guard-agnostic first.
     *
     * @formatter:off
     *
     * @param  list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, definition: \SineMacula\Laravel\Authorization\Support\PermissionDefinition}>  $pairs
     * @return list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, definition: \SineMacula\Laravel\Authorization\Support\PermissionDefinition}>
     *
     * @formatter:on
     */
    private static function sortPairs(array $pairs): array
    {
        \usort($pairs, static fn (array $left, array $right): int => \strcmp($left['definition']->key(), $right['definition']->key()));

        return $pairs;
    }

    /**
     * Order rows by name, then guard, guard-agnostic first.
     *
     * @param  array<\SineMacula\Laravel\Authorization\Models\Permission>  $rows
     * @return list<\SineMacula\Laravel\Authorization\Models\Permission>
     */
    private static function sortRows(array $rows): array
    {
        \usort($rows, static fn (Permission $left, Permission $right): int => \strcmp(self::rowKey($left), self::rowKey($right)));

        return $rows;
    }
}
