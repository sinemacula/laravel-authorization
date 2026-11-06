<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * What a requirement checker found for one authentication requirement (N34):
 * whether it is met, the parts that are not, and the instant until which a met
 * requirement stays met.
 *
 * A met requirement has no unmet parts, and only a met one has an instant it
 * stays met until; anything else is refused on construction. A met requirement
 * with no instant stays met for the session, as far as the checker knows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RequirementResult
{
    /**
     * Create a new requirement result.
     *
     * @param  bool  $isMet
     * @param  list<string>  $unmet
     * @param  \DateTimeImmutable|null  $metUntil
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Whether the requirement is met. */
        public bool $isMet,

        /** The name of each part that is not met; none when the requirement is met. */
        public array $unmet = [],

        /** The instant the met requirement stops being met; null when the checker gives none, or it is unmet. */
        public ?\DateTimeImmutable $metUntil = null,
    ) {
        if ($isMet && $unmet !== []) {
            throw new \InvalidArgumentException('A met authentication requirement has no unmet parts.');
        }

        if (!$isMet && $metUntil !== null) {
            throw new \InvalidArgumentException('Only a met authentication requirement stays met until an instant.');
        }
    }

    /**
     * Return a result for a met requirement, met until the instant given.
     *
     * @param  \DateTimeImmutable|null  $until
     * @return self
     */
    public static function met(?\DateTimeImmutable $until = null): self
    {
        return new self(true, [], $until);
    }

    /**
     * Return a result for a requirement whose parts named are not met.
     *
     * @param  list<string>  $parts
     * @return self
     */
    public static function unmet(array $parts): self
    {
        return new self(false, $parts);
    }
}
