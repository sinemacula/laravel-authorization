<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * Pure diff engine that reconciles enum-derived permission tuples
 * against the current global permission rows.
 *
 * The builder performs no IO: the caller loads the rows (already
 * filtered to `tenant_id IS NULL`, deprecated rows included) and
 * supplies a pre-computed pivot count for reporting. The return
 * value is a structured `PermissionDiff` partitioning every input
 * into exactly one of six buckets.
 *
 * Matching is keyed on `(name, guard)` with `null` and empty-string
 * guards treated as equivalent. Bucket assignment follows the
 * algorithm documented in SPEC §4.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PermissionDiffBuilder
{
    /**
     * Build a diff from the expected tuples and the current rows.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Console\Support\PermissionTuple>  $tuples
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $rows
     * @param  int  $roleReferencesCount
     * @return \SineMacula\Laravel\Authorization\Console\Support\PermissionDiff
     */
    public function build(array $tuples, array $rows, int $roleReferencesCount): PermissionDiff
    {
        $rowsByKey = $this->indexRows($rows);
        $matched   = $this->partitionTuples($tuples, $rowsByKey);
        $orphans   = $this->partitionOrphans($rowsByKey, $matched['matchedKeys']);

        return new PermissionDiff(
            add: $this->sortTuples($matched['add']),
            update: $this->sortPairs($matched['update']),
            reinstate: $this->sortPairs($matched['reinstate']),
            retire: $this->sortRows($orphans['retire']),
            protected: $this->sortRows($orphans['protected']),
            unchanged: $this->sortRows($matched['unchanged']),
            roleReferencesCount: $roleReferencesCount,
        );
    }

    /**
     * Index the supplied rows by their composite `(name, guard)` key.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $rows
     * @return array<string, \SineMacula\Laravel\Authorization\Models\Permission>
     */
    private function indexRows(array $rows): array
    {
        $rowsByKey = [];

        foreach ($rows as $row) {
            $rowsByKey[$this->rowKey($row)] = $row;
        }

        return $rowsByKey;
    }

    /**
     * Classify every tuple into one of four buckets and report the
     * keys that were matched against a DB row.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Console\Support\PermissionTuple>  $tuples
     * @param  array<string, \SineMacula\Laravel\Authorization\Models\Permission>  $rowsByKey
     * @return array{
     *     add: list<\SineMacula\Laravel\Authorization\Console\Support\PermissionTuple>,
     *     update: list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, tuple: \SineMacula\Laravel\Authorization\Console\Support\PermissionTuple}>,
     *     reinstate: list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, tuple: \SineMacula\Laravel\Authorization\Console\Support\PermissionTuple}>,
     *     unchanged: list<\SineMacula\Laravel\Authorization\Models\Permission>,
     *     matchedKeys: array<string, true>
     * }
     */
    private function partitionTuples(array $tuples, array $rowsByKey): array
    {
        $add         = [];
        $update      = [];
        $reinstate   = [];
        $unchanged   = [];
        $matchedKeys = [];

        foreach ($tuples as $tuple) {
            $key = $this->tupleKey($tuple);
            $row = $rowsByKey[$key] ?? null;

            if ($row === null) {
                $add[] = $tuple;
                continue;
            }

            $matchedKeys[$key] = true;

            match (true) {
                $row->deprecated_at !== null        => $reinstate[] = ['row' => $row, 'tuple' => $tuple],
                $this->metadataDrifts($row, $tuple) => $update[]    = ['row' => $row, 'tuple' => $tuple],
                default                             => $unchanged[] = $row,
            };
        }

        return [
            'add'         => $add,
            'update'      => $update,
            'reinstate'   => $reinstate,
            'unchanged'   => $unchanged,
            'matchedKeys' => $matchedKeys,
        ];
    }

    /**
     * Split the rows that no tuple matched into retire candidates and
     * system-protected candidates.
     *
     * @param  array<string, \SineMacula\Laravel\Authorization\Models\Permission>  $rowsByKey
     * @param  array<string, true>  $matchedKeys
     * @return array{retire: list<\SineMacula\Laravel\Authorization\Models\Permission>, protected: list<\SineMacula\Laravel\Authorization\Models\Permission>}
     */
    private function partitionOrphans(array $rowsByKey, array $matchedKeys): array
    {
        $retire        = [];
        $protectedRows = [];

        foreach ($rowsByKey as $key => $row) {
            if (isset($matchedKeys[$key])) {
                continue;
            }

            if ($row->is_system) {
                $protectedRows[] = $row;
                continue;
            }

            $retire[] = $row;
        }

        return ['retire' => $retire, 'protected' => $protectedRows];
    }

    /**
     * Build the match key for a tuple, normalising guard so empty
     * strings collapse to null.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionTuple  $tuple
     * @return string
     */
    private function tupleKey(PermissionTuple $tuple): string
    {
        return $this->compositeKey($tuple->name, $tuple->guard);
    }

    /**
     * Build the match key for a row, normalising guard so empty
     * strings collapse to null.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $row
     * @return string
     */
    private function rowKey(Permission $row): string
    {
        return $this->compositeKey($row->name, $row->guard);
    }

    /**
     * Compose a stable match key from a `(name, guard)` pair.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @return string
     */
    private function compositeKey(string $name, ?string $guard): string
    {
        $normalisedGuard = $guard === null || $guard === '' ? '' : $guard;

        return $name . "\0" . $normalisedGuard;
    }

    /**
     * Determine whether the row's metadata differs from the tuple.
     *
     * Only `description` and `category` participate in drift
     * detection — other columns are either structural (`name`,
     * `guard`, `is_system`, tenant columns) or derived
     * (`deprecated_at`, timestamps).
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $row
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionTuple  $tuple
     * @return bool
     */
    private function metadataDrifts(Permission $row, PermissionTuple $tuple): bool
    {
        return $row->description !== $tuple->description
            || $row->category    !== $tuple->category;
    }

    /**
     * Sort a tuple list by `(name, guard)` ascending, null guards
     * first.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Console\Support\PermissionTuple>  $tuples
     * @return list<\SineMacula\Laravel\Authorization\Console\Support\PermissionTuple>
     */
    private function sortTuples(array $tuples): array
    {
        \usort($tuples, fn (PermissionTuple $a, PermissionTuple $b): int => $this->compareKeys(
            $a->name,
            $a->guard,
            $b->name,
            $b->guard,
        ));

        return $tuples;
    }

    /**
     * Sort a row list by `(name, guard)` ascending, null guards
     * first.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $rows
     * @return list<\SineMacula\Laravel\Authorization\Models\Permission>
     */
    private function sortRows(array $rows): array
    {
        \usort($rows, fn (Permission $a, Permission $b): int => $this->compareKeys(
            $a->name,
            $a->guard,
            $b->name,
            $b->guard,
        ));

        return $rows;
    }

    /**
     * Sort a row/tuple pair list by the tuple's `(name, guard)` —
     * the tuple key and row key agree because the pair is only
     * emitted when both match.
     *
     * @param  list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, tuple: \SineMacula\Laravel\Authorization\Console\Support\PermissionTuple}>  $pairs
     * @return list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, tuple: \SineMacula\Laravel\Authorization\Console\Support\PermissionTuple}>
     */
    private function sortPairs(array $pairs): array
    {
        \usort($pairs, fn (array $a, array $b): int => $this->compareKeys(
            $a['tuple']->name,
            $a['tuple']->guard,
            $b['tuple']->name,
            $b['tuple']->guard,
        ));

        return $pairs;
    }

    /**
     * Three-way compare two `(name, guard)` pairs. Name comparison
     * is straightforward strcmp; guard comparison treats null as
     * sorting before any concrete string so guard-agnostic rows
     * surface first within a given name.
     *
     * @param  string  $leftName
     * @param  string|null  $leftGuard
     * @param  string  $rightName
     * @param  string|null  $rightGuard
     * @return int
     */
    private function compareKeys(string $leftName, ?string $leftGuard, string $rightName, ?string $rightGuard): int
    {
        $nameComparison = \strcmp($leftName, $rightName);

        return $nameComparison !== 0
            ? $nameComparison
            : $this->compareGuards($leftGuard, $rightGuard);
    }

    /**
     * Three-way compare two guard slots. A null guard sorts before
     * any concrete string so guard-agnostic rows surface first
     * within a given name.
     *
     * @param  string|null  $leftGuard
     * @param  string|null  $rightGuard
     * @return int
     */
    private function compareGuards(?string $leftGuard, ?string $rightGuard): int
    {
        if ($leftGuard === $rightGuard) {
            return 0;
        }

        if ($leftGuard === null) {
            return -1;
        }

        return $rightGuard === null ? 1 : \strcmp($leftGuard, $rightGuard);
    }
}
