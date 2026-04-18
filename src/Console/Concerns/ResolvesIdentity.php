<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * Shared identity resolution for Artisan commands.
 *
 * Parses a `{morphType}:{key}` string, resolves the morph alias
 * (or raw class-string), fetches the row via `findOrFail`, and
 * validates the `AuthorizableIdentity` contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait ResolvesIdentity
{
    /**
     * Parse and resolve an identity from the `{morphType}:{key}`
     * format. Returns the model instance on success, or null when
     * the format is invalid, the class cannot be resolved, or the
     * model does not implement `AuthorizableIdentity`.
     *
     * @param  string  $identity
     *
     * @formatter:off
     *
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity)|null
     *
     * @formatter:on
     */
    protected function resolveIdentity(string $identity): (AuthorizableIdentity&Model)|null
    {
        $parts = \explode(':', $identity, 2);

        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            // @var \Illuminate\Console\Command $this
            $this->error('Identity must be in the format {morphType}:{key} (e.g. user:123).');

            return null;
        }

        [$morphType, $key] = $parts;

        $class = Relation::getMorphedModel($morphType) ?? $morphType;

        if (!\class_exists($class)) {
            // @var \Illuminate\Console\Command $this
            $this->error("Cannot resolve morph type '{$morphType}' to a class.");

            return null;
        }

        if (!\is_subclass_of($class, Model::class)) {
            // @var \Illuminate\Console\Command $this
            $this->error("Resolved class '{$class}' is not an Eloquent model.");

            return null;
        }

        /** @var \Illuminate\Database\Eloquent\Model|null $model */
        $model = $class::query()->find($key);

        if ($model === null) {
            // @var \Illuminate\Console\Command $this
            $this->error("No {$class} found with key '{$key}'.");

            return null;
        }

        if (!$model instanceof AuthorizableIdentity) {
            // @var \Illuminate\Console\Command $this
            $this->error($model::class . ' does not implement AuthorizableIdentity.');

            return null;
        }

        /** @var (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity) */
        return $model;
    }
}
