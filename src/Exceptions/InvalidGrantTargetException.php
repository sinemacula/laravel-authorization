<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use Illuminate\Database\Eloquent\Model;

/**
 * Thrown when a grant, revocation or sync is handed something that is not a
 * saved model of the kind it grants: a policy grant given another model, or a
 * name, or a role sync given a permission.
 *
 * The target comes from the calling code, so this is a programming error rather
 * than a client-facing outcome.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidGrantTargetException extends \InvalidArgumentException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $kind
     * @param  mixed  $target
     */
    public function __construct(

        /** The kind of grant: `role`, `permission` or `policy`. */
        private readonly string $kind,

        // The refused target, described in the message.
        mixed $target,
    ) {
        parent::__construct("A {$kind} grant takes a saved {$kind} model" . ($kind === 'policy' ? '' : ' or name') . ', not ' . self::describe($target) . '.');
    }

    /**
     * Return the kind of grant that refused the target.
     *
     * @return string
     */
    public function getKind(): string
    {
        return $this->kind;
    }

    /**
     * Describe the refused target for the message: its class, marked unsaved
     * when it is a model that has not been saved, or its type.
     *
     * @param  mixed  $target
     * @return string
     */
    private static function describe(mixed $target): string
    {
        if (!\is_object($target)) {
            return \get_debug_type($target);
        }

        $unsaved = $target instanceof Model && !$target->exists;

        return ($unsaved ? 'an unsaved ' : '') . $target::class;
    }
}
