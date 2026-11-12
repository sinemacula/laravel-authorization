<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;

/**
 * The change to a definition an operation resource proposes, as values: the
 * role, permission or policy it creates, edits or deletes, the attributes it
 * proposes, for a policy given a new document, that document as it would be
 * stored, and, for a pair of mutually exclusive roles declared or removed, the
 * other role of the pair, as stored. The administration stage weighs these (see
 * `DefinitionConstraints`); policies read the same as the operation resource's
 * attributes, a document by its digest alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DefinitionChange
{
    /**
     * Create a new definition change.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $record
     * @param  array<string, bool|float|int|string|null>  $values
     * @param  array<string, mixed>|null  $document
     * @param  \Illuminate\Database\Eloquent\Model|null  $related
     */
    public function __construct(

        /** The role, permission or policy the change creates, edits or deletes, as read before the change. */
        public Model $record,

        /** The attributes the change proposes, each under the name policies read it by. */
        public array $values = [],

        /** The document a policy is given, as it would be stored; null for no new document, or one that cannot be read. */
        public ?array $document = null,

        /** The other role a pair of mutually exclusive roles names, as stored; null for any other change. */
        public ?Model $related = null,
    ) {}

    /**
     * Determine whether the change proposes the attribute, a null value
     * included.
     *
     * @param  string  $name
     * @return bool
     */
    public function proposes(string $name): bool
    {
        return \array_key_exists($name, $this->values);
    }
}
