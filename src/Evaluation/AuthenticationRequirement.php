<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * An authentication requirement a policy statement states (AUTHZ-8.3, N33): the
 * parts the subject's session must have proved, each with an optional maximum
 * age in seconds.
 *
 * A statement states one with the `authentication_requirement` operator on the
 * reserved key `authentication`, its operand a map of parts, each `{}` or
 * `{"max_age": <seconds>}`:
 *
 * - `additional_verification`: a verification beyond the sign-in;
 * - `multifactor`: authentication with more than one factor;
 * - `phishing_resistant`: a phishing-resistant authenticator;
 * - `assurance_level`: an assurance level of at least `min`, which it requires.
 *
 * The requirement is one test, judged whole by the bound requirement checker,
 * which fetches the proofs itself. Its parts are kept in the order above,
 * whatever order they were written in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthenticationRequirement
{
    /** @var string The operator that states a requirement. */
    public const string OPERATOR = 'authentication_requirement';

    /** @var string The one key the operator tests. */
    public const string KEY = 'authentication';

    /** @var string The part that requires a minimum assurance level. */
    public const string ASSURANCE_LEVEL = 'assurance_level';

    /** @var list<string> Every part a requirement may name, in order. */
    public const array PARTS = ['additional_verification', 'multifactor', 'phishing_resistant', self::ASSURANCE_LEVEL];

    /** @var string The option giving a part's maximum age, in seconds. */
    private const string MAX_AGE = 'max_age';

    /** @var string The option giving the minimum assurance level. */
    private const string MIN = 'min';

    /** @var array<string, int|null> Each part required, by name, with its maximum age in seconds; null when any age will do. */
    public array $parts;

    /**
     * Create a new authentication requirement.
     *
     * @param  array<string, int|null>  $parts
     * @param  string|null  $minimumLevel
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        // Each part required, by name, with its maximum age in seconds.
        array $parts,

        /** The lowest assurance level that meets the `assurance_level` part; null when the part is not required. */
        public ?string $minimumLevel = null,
    ) {
        $error = self::errorOf(self::operandOf($parts, $minimumLevel))
            ?? ($minimumLevel !== null && !\array_key_exists(self::ASSURANCE_LEVEL, $parts) ? 'requirement gives a minimum level without the assurance_level part' : null);

        if ($error !== null) {
            throw new \InvalidArgumentException("Authentication {$error}.");
        }

        $this->parts = \array_intersect_key(\array_replace(\array_fill_keys(self::PARTS, null), $parts), $parts);
    }

    /**
     * Build the requirement a condition's operand states.
     *
     * @param  mixed  $operand
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromOperand(mixed $operand): self
    {
        $error = self::errorOf($operand);

        if ($error !== null) {
            throw new \InvalidArgumentException("Authentication {$error}.");
        }

        /** @var array<string, array{max_age?: int, min?: string}> $operand */
        $parts = \array_map(static fn (array $options): ?int => $options[self::MAX_AGE] ?? null, $operand);

        return new self($parts, $operand[self::ASSURANCE_LEVEL][self::MIN] ?? null);
    }

    /**
     * Describe why an operand states no requirement, or return null when it
     * states one: it must map one or more known parts to their options, each an
     * optional `max_age` of at least one second, and `assurance_level` a
     * non-empty `min`.
     *
     * @param  mixed  $operand
     * @return string|null
     */
    public static function errorOf(mixed $operand): ?string
    {
        if (!\is_array($operand) || $operand === [] || \array_is_list($operand)) {
            return 'requirement must map one or more parts (' . \implode(', ', self::PARTS) . ') to their options';
        }

        foreach ($operand as $part => $options) {
            $error = \in_array($part, self::PARTS, true) ? self::partError($part, $options) : "requirement names an unknown part '{$part}'";

            if ($error !== null) {
                return $error;
            }
        }

        return null;
    }

    /**
     * Return the name of every part required, in order.
     *
     * @return list<string>
     */
    public function names(): array
    {
        return \array_keys($this->parts);
    }

    /**
     * Return the most seconds since the part was proved that still meets it, or
     * null when any age will do or the part is not required.
     *
     * @param  string  $part
     * @return int|null
     */
    public function maxAge(string $part): ?int
    {
        return $this->parts[$part] ?? null;
    }

    /**
     * Return the requirement as a map of each part to its options: its maximum
     * age (null for any) and, for `assurance_level`, its minimum level.
     *
     * @return array<string, array{max_age: int|null, min?: string}>
     */
    public function toArray(): array
    {
        $parts = [];

        foreach ($this->parts as $part => $maxAge) {
            $parts[$part] = [self::MAX_AGE => $maxAge] + ($part === self::ASSURANCE_LEVEL && $this->minimumLevel !== null ? [self::MIN => $this->minimumLevel] : []);
        }

        return $parts;
    }

    /**
     * Describe why one known part's options are malformed, or return null when
     * they are well formed.
     *
     * @param  string  $part
     * @param  mixed  $options
     * @return string|null
     */
    private static function partError(string $part, mixed $options): ?string
    {
        $allowed  = $part === self::ASSURANCE_LEVEL ? [self::MAX_AGE, self::MIN] : [self::MAX_AGE];
        $given    = \is_array($options) ? $options : null;
        $unknown  = $given === null ? [] : \array_diff(\array_keys($given), $allowed);
        $hasAge   = $given === null                 || !\array_key_exists(self::MAX_AGE, $given) || self::isMaxAge($given[self::MAX_AGE]);
        $hasLevel = $part !== self::ASSURANCE_LEVEL || self::isLevel($given[self::MIN] ?? null);

        return match (true) {
            $given === null => "requirement part '{$part}' must be an object of options",
            $unknown !== [] => "requirement part '{$part}' has unknown options: " . \implode(', ', $unknown),
            !$hasAge        => "requirement part '{$part}' max_age must be a whole number of seconds, at least 1",
            !$hasLevel      => "requirement part '{$part}' requires min, a non-empty string",
            default         => null,
        };
    }

    /**
     * Return the operand that states the parts and the minimum level, for the
     * same checks a condition's operand gets.
     *
     * @param  array<array-key, mixed>  $parts
     * @param  string|null  $minimumLevel
     * @return array<array-key, mixed>
     */
    private static function operandOf(array $parts, ?string $minimumLevel): array
    {
        $operand = [];

        foreach ($parts as $part => $maxAge) {
            $operand[$part] = ($maxAge === null ? [] : [self::MAX_AGE => $maxAge])
                + ($part === self::ASSURANCE_LEVEL && $minimumLevel !== null ? [self::MIN => $minimumLevel] : []);
        }

        return $operand;
    }

    /**
     * Determine whether the value is a maximum age: a whole number of seconds,
     * at least one.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isMaxAge(mixed $value): bool
    {
        return \is_int($value) && $value >= 1;
    }

    /**
     * Determine whether the value is an assurance level: a string that is not
     * empty or blank.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isLevel(mixed $value): bool
    {
        return \is_string($value) && \trim($value) !== '';
    }
}
