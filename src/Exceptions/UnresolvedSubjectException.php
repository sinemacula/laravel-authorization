<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a console subject resolver cannot resolve the saved subject
 * reference it is given (see `Contracts\ConsoleSubjectResolver`): the reference
 * is malformed, its type is no Eloquent model, no row has its key, the model
 * cannot be the subject of a check, or the subject resolver maps it to a
 * subject that is not about it.
 *
 * It is an invalid invocation, which `authorization:why` reports and exits 2
 * for, rather than a denial. The message names the reference as it was given,
 * which the command escapes before it is written, and no other value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnresolvedSubjectException extends \InvalidArgumentException
{
    /**
     * Refuse a reference that is not in the `{morphType}:{key}` format.
     *
     * @return self
     */
    public static function malformed(): self
    {
        return new self('The subject must be in the format {morphType}:{key} (e.g. user:1).');
    }

    /**
     * Refuse a morph type that names no Eloquent model, through the morph map
     * or as a class name.
     *
     * @param  string  $type
     * @return self
     */
    public static function unknownType(string $type): self
    {
        return new self("The subject type '{$type}' is not an Eloquent model.");
    }

    /**
     * Refuse a reference no row has the key of.
     *
     * @param  string  $reference
     * @return self
     */
    public static function notFound(string $reference): self
    {
        return new self("No subject '{$reference}' was found.");
    }

    /**
     * Refuse a model that cannot be the subject of a check: its principal is
     * not a saved authorizable identity.
     *
     * @param  string  $reference
     * @return self
     */
    public static function unsupported(string $reference): self
    {
        return new self("The subject '{$reference}' cannot be checked: its principal is not a saved authorizable identity.");
    }

    /**
     * Refuse a model the subject resolver maps to a subject that is not about
     * it, neither its principal nor its identity, so which subject is meant
     * cannot be told.
     *
     * @param  string  $reference
     * @return self
     */
    public static function ambiguous(string $reference): self
    {
        return new self("The subject '{$reference}' is ambiguous: the subject resolver maps it to a subject that is not about it.");
    }
}
