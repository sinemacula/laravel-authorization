<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a role, permission or policy service is handed a model of its
 * kind that has not been saved, to rename, describe, rewrite, delete or
 * re-parent, or as the parent or the role a permission is granted on.
 *
 * Saving such a model would create a record outside `create()`, and reading its
 * missing key as a parent would clear a role's parent. The model comes from the
 * calling code, so this is a programming error rather than a client-facing
 * outcome.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnsavedRecordException extends \InvalidArgumentException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $kind
     * @param  object  $record
     */
    public function __construct(

        /** The kind of record: `role`, `permission` or `policy`. */
        private readonly string $kind,

        // The unsaved model, named in the message.
        object $record,
    ) {
        parent::__construct("The {$kind} service takes a saved {$kind}, not an unsaved " . $record::class . '.');
    }

    /**
     * Return the kind of record that was refused.
     *
     * @return string
     */
    public function getKind(): string
    {
        return $this->kind;
    }
}
