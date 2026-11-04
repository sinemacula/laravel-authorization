<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

/**
 * Shared `is_system` row-protection hooks for the primitive authorization
 * models. Every change to a persisted system row, clearing the flag included,
 * is refused unless `forceSystem()` unlocks it; consumers supply the per-model
 * exception factory.
 *
 * The guard runs on the model's `updating` and `deleting` events, so writes
 * that fire no model events skip it: `saveQuietly()`, `deleteQuietly()`, and
 * mass updates or deletes through the query builder. These are an explicit
 * developer bypass, outside the package's own write paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasSystemProtection // @phpstan-ignore trait.unused
{
    /** @var string Name reported for a system record loaded without its name or key. */
    private const string UNNAMED_SYSTEM_RECORD = '[unnamed]';

    /** @var bool Per-instance single-use bypass flag for the next protected mutation. */
    private bool $systemProtectionBypassed = false;

    /**
     * Unlock the next protected mutation on this instance. The bypass is
     * per-instance, single-use, in-memory, and consumed by the guard clause on
     * the next protected operation.
     *
     * @return static
     */
    public function forceSystem(): static
    {
        $this->systemProtectionBypassed = true;

        return $this;
    }

    /**
     * Construct the per-model exception raised when a protected mutation is
     * refused. The operation label (`'delete'`, `'unprotect'`, `'rename'`,
     * `'document-rewrite'` or `'modify'`) is carried on the exception alongside
     * the row's canonical name.
     *
     * @param  string  $operation
     * @return \Throwable
     */
    abstract protected function systemProtectionException(string $operation): \Throwable;

    /**
     * Register the `deleting` / `updating` / `saved` hooks that enforce the
     * system-row protection invariant. The `updating` hook names the operation
     * after the most significant attribute found in `getDirty()`.
     *
     * @return void
     */
    protected static function bootHasSystemProtection(): void
    {
        static::deleting(static function (self $model): void {
            $model->assertSystemProtectionAllows('delete');
        });

        static::updating(static function (self $model): void {
            $operation = $model->pendingSystemProtectedOperation();

            if ($operation === null) {
                return;
            }

            $model->assertSystemProtectionAllows($operation);
        });

        // Clear the bypass flag after every completed save so it cannot hop
        // across an intervening unprotected save (e.g. a `touch()` or a save
        // with nothing dirty) and silently unlock the next protected change.
        // `saved` fires after `updating` has had a chance to consume the flag
        // for a legitimate protected mutation, so this reset is strictly
        // idempotent on that path.
        static::saved(static function (self $model): void {
            $model->systemProtectionBypassed = false;
        });
    }

    /**
     * Decide whether the supplied mutation is allowed against the current
     * instance. Consumes the bypass flag so a second protected operation
     * re-arms the protection.
     *
     * @param  string  $operation
     * @return void
     *
     * @throws \Throwable
     */
    protected function assertSystemProtectionAllows(string $operation): void
    {
        if (!$this->isPersistedAsSystem()) {
            return;
        }

        if ($this->systemProtectionBypassed) {
            $this->systemProtectionBypassed = false;

            return;
        }

        throw $this->systemProtectionException($operation);
    }

    /**
     * Return the name the refusal reports for this record. The persisted name
     * is used, not the dirty one, so a refused rename reports the record that
     * was targeted rather than the name it would have taken. A record loaded
     * without its name falls back to its key, and one loaded without either is
     * reported as `[unnamed]`, so the refusal is never lost to a missing
     * attribute.
     *
     * @return string
     */
    protected function systemProtectedName(): string
    {
        $name = $this->getOriginal('name');

        if (\is_string($name)) {
            return $name;
        }

        $key = $this->getKeyForSaveQuery();

        return \is_scalar($key) ? (string) $key : self::UNNAMED_SYSTEM_RECORD;
    }

    /**
     * Determine whether the row is a system row as persisted. The original
     * value is read, not the dirty one, so clearing `is_system` in the same
     * update (or before a delete) cannot lift the protection it is meant to
     * guard. When the instance was loaded without the column, the flag is read
     * from the database on the write connection, so a lagging read replica
     * cannot report a stale value, and a row that cannot be found counts as
     * system so the guard fails closed.
     *
     * @return bool
     */
    private function isPersistedAsSystem(): bool
    {
        if (\array_key_exists('is_system', $this->original)) {
            return (bool) $this->original['is_system'];
        }

        $persisted = $this->newQueryWithoutScopes()
            ->whereKey($this->getKeyForSaveQuery())
            ->toBase()
            ->useWritePdo()
            ->value('is_system');

        return (bool) ($persisted ?? true);
    }

    /**
     * Return the operation label for the pending update when any attribute
     * other than the update timestamp is dirty, or null otherwise. Whether the
     * row is a system row is left to the guard, so a `touch()` or a clean save
     * never reads the flag. Labels, most significant first: `'unprotect'` for
     * `is_system`, `'rename'` for `name`, `'document-rewrite'` for `document`,
     * `'modify'` for anything else.
     *
     * @return string|null
     */
    private function pendingSystemProtectedOperation(): ?string
    {
        $dirty = $this->systemProtectedChanges();

        if ($dirty === []) {
            return null;
        }

        return self::systemProtectedOperationLabel($dirty);
    }

    /**
     * Return the dirty attributes the guard protects: every dirty attribute
     * except the update timestamp, so a `touch()` stays allowed.
     *
     * @return array<string, mixed>
     */
    private function systemProtectedChanges(): array
    {
        /** @var array<string, mixed> $dirty */
        $dirty = $this->getDirty();

        if ($this->usesTimestamps()) {
            unset($dirty[$this->getUpdatedAtColumn()]);
        }

        return $dirty;
    }

    /**
     * Map the protected changes onto the canonical label of the most
     * significant one.
     *
     * @param  array<string, mixed>  $dirty
     * @return string
     */
    private static function systemProtectedOperationLabel(array $dirty): string
    {
        $labels = [
            'is_system' => 'unprotect',
            'name'      => 'rename',
            'document'  => 'document-rewrite',
        ];

        foreach ($labels as $field => $label) {
            if (\array_key_exists($field, $dirty)) {
                return $label;
            }
        }

        return 'modify';
    }
}
