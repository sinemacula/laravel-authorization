<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a console subject resolver cannot resolve the saved subject
 * reference it is given (see `Contracts\ConsoleSubjectResolver`): the reference
 * is malformed, its type is no Eloquent model, no row has its key, the model
 * cannot be the subject of a check, the subject resolver maps it to a subject
 * that is not about it, or resolving it failed.
 *
 * It is an invalid invocation, which `authorization:why` and
 * `authorization:review` report and exit 2 for, rather than a denial. Each
 * refusal's code says which it is (see the constants). Its message names the
 * reference as it was given, and no other value; when resolving failed, it
 * names neither the reference nor the failure. A command never writes that
 * message: it writes the refusal `namingOnly()` its argument gives, which says
 * what is wrong by the argument's name alone, never the value given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnresolvedSubjectException extends \InvalidArgumentException
{
    /** @var int The code of a reference that is not in the `{morphType}:{key}` format. */
    public const int MALFORMED = 1;

    /** @var int The code of a morph type that names no Eloquent model. */
    public const int UNKNOWN_TYPE = 2;

    /** @var int The code of a reference no row has the key of. */
    public const int NOT_FOUND = 3;

    /** @var int The code of a model that cannot be the subject of a check. */
    public const int UNSUPPORTED = 4;

    /** @var int The code of a model mapped to a subject that is not about it. */
    public const int AMBIGUOUS = 5;

    /** @var int The code of a subject that something failed while resolving. */
    public const int UNRESOLVABLE = 6;

    /**
     * Refuse a reference that is not in the `{morphType}:{key}` format.
     *
     * @return self
     */
    public static function malformed(): self
    {
        return new self('The subject must be in the format {morphType}:{key} (e.g. user:1).', self::MALFORMED);
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
        return new self("The subject type '{$type}' is not an Eloquent model.", self::UNKNOWN_TYPE);
    }

    /**
     * Refuse a reference no row has the key of.
     *
     * @param  string  $reference
     * @return self
     */
    public static function notFound(string $reference): self
    {
        return new self("No subject '{$reference}' was found.", self::NOT_FOUND);
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
        return new self("The subject '{$reference}' cannot be checked: its principal is not a saved authorizable identity.", self::UNSUPPORTED);
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
        return new self("The subject '{$reference}' is ambiguous: the subject resolver maps it to a subject that is not about it.", self::AMBIGUOUS);
    }

    /**
     * Refuse a subject that could not be resolved because something failed
     * while resolving it, such as the database lookup or the subject resolver,
     * kept as the previous exception. The message names neither the reference
     * nor the failure, which may hold a value.
     *
     * @param  \Throwable  $previous
     * @return self
     */
    public static function unresolvable(\Throwable $previous): self
    {
        return new self('The subject could not be resolved.', self::UNRESOLVABLE, $previous);
    }

    /**
     * Return the refusal as a command writes it: what is wrong, by the name of
     * the argument the reference was given as alone, never the reference or its
     * type; a refusal of any other code, as a resolver of the application's own
     * may throw, as one that could not be resolved. The refusal keeps its code
     * and is kept as the previous exception.
     *
     * @param  string  $argument
     * @return self
     */
    public function namingOnly(string $argument): self
    {
        $message = match ($this->getCode()) {
            self::MALFORMED    => "The {$argument} must be in the format {morphType}:{key} (e.g. user:1).",
            self::UNKNOWN_TYPE => "The {$argument}'s type is not an Eloquent model.",
            self::NOT_FOUND    => "The {$argument} names no saved row.",
            self::UNSUPPORTED  => "The {$argument} cannot be checked: its principal is not a saved authorizable identity.",
            self::AMBIGUOUS    => "The {$argument} is ambiguous: the subject resolver maps it to a subject that is not about it.",
            default            => "The {$argument} could not be resolved.",
        };

        return new self($message, $this->getCode(), $this);
    }
}
