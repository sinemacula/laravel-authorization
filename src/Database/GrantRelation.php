<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Database\Query\Builder;

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
 * Given the query of the rows to read in place of the grant table, the relation
 * joins those rows under the table's name, so every constraint on the table's
 * columns reads them as it reads the table; a write through the relation still
 * goes to the table itself. The roles relation reads its role grants and the
 * live break-glass activations this way (see `BreakGlassActivations`).
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
    /** @var \Illuminate\Database\Query\Builder|null The rows read in place of the grant table, or null for the table itself. */
    private ?Builder $rows = null;

    /**
     * Read the rows given in place of the grant table, joined under the table's
     * name in place of the table the relation was built joining; none leaves
     * the table joined.
     *
     * @param  \Illuminate\Database\Query\Builder|null  $rows
     * @return $this
     */
    public function readingRows(?Builder $rows): self
    {
        if ($rows === null) {
            return $this;
        }

        $this->rows = $rows;

        // The constructor's join of the grant table is its only one.
        $this->query->getQuery()->joins = [];

        return $this->performJoin();
    }

    /**
     * Constrain an eager load to the grantees' grants, by their keys as
     * strings.
     *
     * @param  array<int, TDeclaringModel>  $models
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
     * Join the grant table, or the rows read in place of it, under the table's
     * name.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<TRelatedModel>|null  $query
     * @return $this
     */
    #[\Override]
    protected function performJoin($query = null): self
    {
        if ($this->rows === null) {
            return parent::performJoin($query);
        }

        ($query ?? $this->query)->joinSub($this->rows, $this->table, $this->getQualifiedRelatedKeyName(), '=', $this->getQualifiedRelatedPivotKeyName());

        return $this;
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
