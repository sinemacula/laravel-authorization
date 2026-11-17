<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableGrantee;

/**
 * Shared grantee resolution for Artisan commands.
 *
 * Parses a `{morphType}:{key}` string, resolves the morph alias (or raw
 * class-string), fetches the row via `findOrFail`, and validates the
 * `AuthorizableGrantee` contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait ResolvesGrantee
{
    /**
     * Parse and resolve a grantee from the `{morphType}:{key}` format. Returns
     * the model instance on success, or null when the format is invalid, the
     * class cannot be resolved, or the model does not implement
     * `AuthorizableGrantee`.
     *
     * @param  string  $grantee
     *
     * @formatter:off
     *
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authorization\Contracts\AuthorizableGrantee)|null
     *
     * @formatter:on
     */
    protected function resolveGrantee(string $grantee): (AuthorizableGrantee&Model)|null
    {
        $parts = \explode(':', $grantee, 2);

        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            $this->error('Grantee must be in the format {morphType}:{key} (e.g. user:123).');

            return null;
        }

        [$morphType, $key] = $parts;

        $class = Relation::getMorphedModel($morphType) ?? $morphType;

        if (!\class_exists($class)) {
            $this->error("Cannot resolve morph type '{$morphType}' to a class.");

            return null;
        }

        if (!\is_subclass_of($class, Model::class)) {
            $this->error("Resolved class '{$class}' is not an Eloquent model.");

            return null;
        }

        /** @var \Illuminate\Database\Eloquent\Model|null $model */
        $model = $class::query()->find($key);

        if ($model === null) {
            $this->error("No {$class} found with key '{$key}'.");

            return null;
        }

        if (!$model instanceof AuthorizableGrantee) {
            $this->error($model::class . ' does not implement AuthorizableGrantee.');

            return null;
        }

        /** @var (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authorization\Contracts\AuthorizableGrantee) */
        return $model;
    }
}
