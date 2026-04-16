<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

/**
 * Shared system-row protection for the primitive authorization
 * models (`Role`, `Permission`, `Policy`).
 *
 * A row with `is_system = true` is treated as platform-shipped and
 * refuses `delete` plus any mutation to the protected-attribute
 * list returned by `systemProtectedFields()`. Each consuming model
 * declares:
 *
 * - `systemProtectedFields()` — the attribute names whose dirty
 *   state triggers the guard on `updating` (e.g. `['name']` for
 *   Role / Permission, `['name', 'document']` for Policy).
 * - `systemProtectionException(string $operation)` — factory for
 *   the per-model exception thrown on refusal. The returned
 *   exception is raised verbatim so audit consumers keep the
 *   per-model type discrimination they rely on.
 *
 * The escape hatch is per-instance, single-use, and in-memory:
 * `forceSystem()` unlocks the next protected mutation, and the
 * next `saved` event clears the flag so it cannot hop across an
 * intervening non-protected save (#75).
 *
 * Closes the triplicated protection pattern flagged in #92.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasSystemProtection // @phpstan-ignore trait.unused
{
    /**
     * Per-instance escape-hatch flag. When true, the next
     * protected mutation bypasses the system-row check and resets
     * to false on completion. Invoked via `forceSystem()` — never
     * persisted, never inherited across instances.
     *
     * @var bool
     */
    private bool $systemProtectionBypassed = false;

    /**
     * Unlock the next protected mutation (delete or a change to
     * any attribute in `systemProtectedFields()`) on this
     * instance. Returns `$this` for chaining:
     *
     *     $model->forceSystem()->delete();
     *
     * The bypass is **per-instance, single-use, and in-memory** —
     * it never persists to the database, never leaks across
     * instances (a `$model->fresh()` drops it), and resets to
     * false the moment the guard clause consults it.
     *
     * @return static
     */
    public function forceSystem(): static
    {
        $this->systemProtectionBypassed = true;

        return $this;
    }

    /**
     * Return the attribute names whose dirty state triggers the
     * system-protection guard on `updating`. For `Role` and
     * `Permission` this is `['name']`; for `Policy` it is
     * `['name', 'document']` — the document carries the authorization
     * payload and is covered alongside the label (#91).
     *
     * @return list<string>
     */
    abstract protected function systemProtectedFields(): array;

    /**
     * Construct the per-model exception raised when a protected
     * mutation is refused. The caller passes the operation label
     * (e.g. `'delete'`, `'rename'`, `'document-rewrite'`); the
     * exception carries the row's canonical name so audit
     * consumers can identify the offending target.
     *
     * @param  string  $operation
     * @return \Throwable
     */
    abstract protected function systemProtectionException(string $operation): \Throwable;

    /**
     * Register the `deleting` / `updating` / `saved` hooks that
     * enforce the system-row protection invariant. The `updating`
     * hook inspects `systemProtectedFields()` and names the
     * operation after the first protected attribute found in
     * `getDirty()` — `'rename'` for a `'name'` change,
     * `'document-rewrite'` for a `'document'` change, or the
     * generic `'modify'` fallback when a consumer-supplied trait
     * declares a surface that does not match those canonical
     * labels.
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

            if ($operation !== null) {
                $model->assertSystemProtectionAllows($operation);
            }
        });

        // Clear the bypass flag after every completed save so it
        // cannot hop across an intervening non-protected mutation
        // (e.g. a description update) and silently unlock the
        // next protected change. `saved` fires after `updating`
        // has had a chance to consume the flag for a legitimate
        // protected mutation, so this reset is strictly
        // idempotent on that path.
        static::saved(static function (self $model): void {
            $model->systemProtectionBypassed = false;
        });
    }

    /**
     * Decide whether the supplied mutation is allowed against the
     * current instance. Consumes the bypass flag so a second
     * protected operation on the same instance re-arms the
     * protection.
     *
     * @param  string  $operation
     * @return void
     *
     * @throws \Throwable
     */
    protected function assertSystemProtectionAllows(string $operation): void
    {
        if ((bool) $this->getAttribute('is_system') === false) {
            return;
        }

        if ($this->systemProtectionBypassed) {
            $this->systemProtectionBypassed = false;

            return;
        }

        throw $this->systemProtectionException($operation);
    }

    /**
     * Return the operation label for the pending update when a
     * protected attribute is dirty, or null when the update
     * touches only non-protected attributes. Only considered on
     * system rows — non-system rows pass through every path
     * without consulting this helper.
     *
     * The label follows the established per-field convention:
     * `'rename'` for a `'name'` change, `'document-rewrite'` for
     * a `'document'` change; anything else falls back to the
     * generic `'modify'` label so a consumer-supplied protected
     * field still names its operation in a way audit consumers
     * can reason about.
     *
     * @return string|null
     */
    private function pendingSystemProtectedOperation(): ?string
    {
        if (!(bool) $this->getAttribute('is_system')) {
            return null;
        }

        /** @var array<string, mixed> $dirty */
        $dirty = $this->getDirty();

        foreach ($this->systemProtectedFields() as $field) {
            if (\array_key_exists($field, $dirty)) {
                return self::systemProtectedOperationLabel($field);
            }
        }

        return null;
    }

    /**
     * Map a protected-field name onto its canonical operation
     * label. Kept static so the label table lives in one place
     * and the `updating` hook can name its refusal without
     * branching per model.
     *
     * @param  string  $field
     * @return string
     */
    private static function systemProtectedOperationLabel(string $field): string
    {
        return match ($field) {
            'name'     => 'rename',
            'document' => 'document-rewrite',
            default    => 'modify',
        };
    }
}
