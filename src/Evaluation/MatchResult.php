<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;

/**
 * Outcome of testing a statement, or one of its parts, with the detail the
 * trace records for it.
 *
 * The detail names what decided the outcome (a missing key, an unknown
 * operator) and never carries a context value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class MatchResult
{
    /**
     * Create a new match result.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome  $outcome
     * @param  string  $detail
     * @param  array<string, bool>|null  $conditions
     * @param  \SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement|null  $unmetRequirement
     */
    public function __construct(

        /** The outcome of the test. */
        public MatchOutcome $outcome,

        /** What decided the outcome, for diagnostics; empty when it matched. */
        public string $detail = '',

        /** Each condition key a statement tested, with whether it held; null when the statement does not name the action and the resource. */
        public ?array $conditions = null,

        /** The authentication requirement that alone kept an allow statement from applying; null when there is none. */
        public ?UnmetRequirement $unmetRequirement = null,
    ) {}

    /**
     * Return the result with the condition keys tested and whether each held.
     *
     * @param  array<string, bool>  $conditions
     * @return self
     */
    public function withConditions(array $conditions): self
    {
        return new self($this->outcome, $this->detail, $conditions, $this->unmetRequirement);
    }

    /**
     * Return the result with the authentication requirement that alone kept the
     * statement from applying, or with none.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement|null  $unmetRequirement
     * @return self
     */
    public function withUnmetRequirement(?UnmetRequirement $unmetRequirement): self
    {
        return new self($this->outcome, $this->detail, $this->conditions, $unmetRequirement);
    }

    /**
     * Build a result for a test that holds.
     *
     * @return self
     */
    public static function matches(): self
    {
        static $shared = null;

        return $shared ??= new self(MatchOutcome::MATCHES);
    }

    /**
     * Build a result for a test that definitely does not hold.
     *
     * @param  string  $detail
     * @return self
     */
    public static function doesNotMatch(string $detail = ''): self
    {
        // Most statements of a policy do not apply to a check, so the result is
        // shared rather than built each time; details are a fixed set of
        // phrases, never context values.
        static $shared = [];

        return $shared[$detail] ??= new self(MatchOutcome::DOES_NOT_MATCH, $detail);
    }

    /**
     * Build a result for an authentication requirement that is not met: a test
     * that definitely does not hold, carrying the requirement and its unmet
     * parts.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement  $unmet
     * @return self
     */
    public static function unmet(UnmetRequirement $unmet): self
    {
        return new self(MatchOutcome::DOES_NOT_MATCH, 'the authentication requirement is not met', null, $unmet);
    }

    /**
     * Build a result for a test that could not be decided.
     *
     * @param  string  $detail
     * @return self
     */
    public static function undecidable(string $detail): self
    {
        return new self(MatchOutcome::UNDECIDABLE, $detail);
    }

    /**
     * Build a result for a malformed test.
     *
     * @param  string  $detail
     * @return self
     */
    public static function invalid(string $detail): self
    {
        return new self(MatchOutcome::INVALID, $detail);
    }

    /**
     * Build a result from a plain boolean test.
     *
     * @param  bool  $holds
     * @return self
     */
    public static function fromBool(bool $holds): self
    {
        return $holds ? self::matches() : self::doesNotMatch();
    }

    /**
     * Combine this result with another part of the same conjunction, keeping
     * whichever outcome has the higher precedence.
     *
     * @param  self  $other
     * @return self
     */
    public function and(self $other): self
    {
        return $other->outcome->precedence() > $this->outcome->precedence() ? $other : $this;
    }

    /**
     * Determine whether the test holds.
     *
     * @return bool
     */
    public function holds(): bool
    {
        return $this->outcome === MatchOutcome::MATCHES;
    }
}
