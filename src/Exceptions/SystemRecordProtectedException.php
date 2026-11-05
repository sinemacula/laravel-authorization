<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a system-flagged role, permission or policy would be deleted,
 * edited or have its system flag cleared without the explicit `forceSystem()`
 * escape hatch.
 *
 * Catch this to handle a refused change to any system record; each kind of
 * record has its own subclass. The exception carries the record's persisted
 * name, or its key when it was loaded without one, so audit and error reporting
 * can identify the offending target.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class SystemRecordProtectedException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $kind
     * @param  string  $recordName
     * @param  string  $operation
     */
    public function __construct(

        // Kind of record, such as "role", for the message.
        string $kind,

        /** Name of the record whose mutation was refused. */
        private readonly string $recordName,

        /** Operation that was refused, such as "delete" or "modify". */
        private readonly string $operation,
    ) {
        parent::__construct(
            "Refusing to {$operation} system {$kind} '{$recordName}'."
                . ' Call `forceSystem()` on the model before the operation to override.',
            403,
        );
    }

    /**
     * Return the name of the record that triggered the protection.
     *
     * @return string
     */
    public function getRecordName(): string
    {
        return $this->recordName;
    }

    /**
     * Return the operation that was refused.
     *
     * @return string
     */
    public function getOperation(): string
    {
        return $this->operation;
    }
}
