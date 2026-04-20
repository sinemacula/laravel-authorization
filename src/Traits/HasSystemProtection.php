<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

/**
 * Shared `is_system` row-protection hooks for the primitive authorization
 * models. Consumers declare the protected-field list and per-model exception
 * factory; `forceSystem()` provides a per-instance, single-use bypass.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasSystemProtection // @phpstan-ignore trait.unused
{
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
     * Return the attribute names whose dirty state triggers the
     * system-protection guard on `updating`. `Role` and `Permission` return
     * `['name']`; `Policy` returns `['name', 'document']`.
     *
     * @return list<string>
     */
    abstract protected function systemProtectedFields(): array;

    /**
     * Construct the per-model exception raised when a protected mutation is
     * refused. The operation label (e.g. `'delete'`, `'rename'`,
     * `'document-rewrite'`) is carried on the exception alongside the row's
     * canonical name.
     *
     * @param  string  $operation
     * @return \Throwable
     */
    abstract protected function systemProtectionException(string $operation): \Throwable;

    /**
     * Register the `deleting` / `updating` / `saved` hooks that enforce the
     * system-row protection invariant. The `updating` hook names the operation
     * after the first protected attribute found in `getDirty()`.
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
     * Return the operation label for the pending update when a protected
     * attribute is dirty on a system row, or null otherwise. Labels: `'rename'`
     * for `name`, `'document-rewrite'` for `document`, `'modify'` for anything
     * else.
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
            if (array_key_exists($field, $dirty)) {
                return self::systemProtectedOperationLabel($field);
            }
        }

        return null;
    }

    /**
     * Map a protected-field name onto its canonical operation label.
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
