<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use Illuminate\Database\Eloquent\Model;

/**
 * Thrown when a grant, revocation or sync is handed a grantee it cannot write a
 * grant for: a model that has not been saved or has no key, or a grantee
 * reference with an empty type or key.
 *
 * Writing such a grant would key it to an empty identity that every other
 * unsaved model of the type shares, and that the model, once saved, does not
 * hold. The grantee comes from the calling code, so this is a programming error
 * rather than a client-facing outcome.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidGranteeException extends \InvalidArgumentException
{
    /**
     * Create a new exception instance.
     *
     * @param  object  $grantee
     */
    public function __construct(object $grantee)
    {
        parent::__construct('A grant takes a saved grantee with a type and a key, not ' . self::describe($grantee) . '.');
    }

    /**
     * Describe the refused grantee for the message: its class, marked unsaved
     * when it is a model that has not been saved, else incomplete.
     *
     * @param  object  $grantee
     * @return string
     */
    private static function describe(object $grantee): string
    {
        $unsaved = $grantee instanceof Model && !$grantee->exists;

        return ($unsaved ? 'an unsaved ' : 'an incomplete ') . $grantee::class;
    }
}
