<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Database\Eloquent\Relations\MorphToMany;

/**
 * A grantee's relation onto one kind of grant, comparing the grantee's key as
 * the string the grant tables store.
 *
 * The grant tables keep `authorizable_id` as a string, so a grantee keyed by
 * integers, UUIDs or ULIDs alike can hold grants. PostgreSQL has no operator
 * comparing a string column with an integer, so a stock relation over an
 * integer-keyed grantee fails there, and Laravel inlines integer keys into an
 * eager load as raw integers. This relation binds the key as a string, alone
 * and eager-loaded, on every database.
 *
 * @template TRelatedModel of \Illuminate\Database\Eloquent\Model
 * @template TDeclaringModel of \Illuminate\Database\Eloquent\Model
 * @template TPivotModel of \Illuminate\Database\Eloquent\Relations\MorphPivot = \Illuminate\Database\Eloquent\Relations\MorphPivot
 * @template TAccessor of string = 'pivot'
 *
 * @extends \Illuminate\Database\Eloquent\Relations\MorphToMany<TRelatedModel, TDeclaringModel, TPivotModel, TAccessor>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GrantRelation extends MorphToMany
{
    /**
     * Constrain an eager load to the grantees' grants, by their keys as
     * strings.
     *
     * @param  array<int, \Illuminate\Database\Eloquent\Model>  $models
     * @return void
     */
    #[\Override]
    public function addEagerConstraints(array $models): void
    {
        $keys = \array_map(static fn (mixed $key): string => (string) $key, $this->getKeys($models, $this->parentKey)); // @phpstan-ignore cast.string

        $this->whereInEager('whereIn', $this->getQualifiedForeignPivotKeyName(), $keys);
        $this->query->where($this->qualifyPivotColumn($this->morphType), $this->morphClass);
    }

    /**
     * Constrain the grants to the grantee's, by its key as a string and its
     * morph type.
     *
     * @return $this
     */
    #[\Override]
    protected function addWhereConstraints(): self
    {
        /** @var scalar $key */
        $key = $this->parent->getAttribute($this->parentKey);

        $this->query->where($this->getQualifiedForeignPivotKeyName(), '=', (string) $key);
        $this->query->where($this->qualifyPivotColumn($this->morphType), $this->morphClass);

        return $this;
    }
}
