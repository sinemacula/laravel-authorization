<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Subject;

/**
 * How long a subject holds a right, or a policy, in the scope in place, each
 * read once (see `HeldLifetime`), for the grantable route of a batch of
 * delegated grants (see `Possession`): every grantable right of one batch is
 * decided under the same right, and often through the same policies, so its
 * lifetime is read once however many permissions the batch weighs.
 *
 * Use one for a single scope only: the lifetimes it remembers are those of the
 * scope in place when each was first read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class HeldLifetimes
{
    /** @var array<string, int|null> The lifetimes read so far, by what is held. */
    private array $read = [];

    /**
     * Create the lifetimes of the subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     */
    public function __construct(

        /** The subject whose lifetimes are read. */
        private readonly Subject $subject,
    ) {}

    /**
     * Return until when the subject holds the right, as `HeldLifetime::of()`
     * reads it, reading it once.
     *
     * @param  string  $right
     * @return int|null
     */
    public function of(string $right): ?int
    {
        $key = 'right:' . $right;

        if (!\array_key_exists($key, $this->read)) {
            $this->read[$key] = HeldLifetime::of($this->subject, $right);
        }

        return $this->read[$key];
    }

    /**
     * Return until when the policy with the key is attached to the subject, as
     * `HeldLifetime::ofPolicy()` reads it, reading it once.
     *
     * @param  string  $policy
     * @return int|null
     */
    public function ofPolicy(string $policy): ?int
    {
        $key = 'policy:' . $policy;

        if (!\array_key_exists($key, $this->read)) {
            $this->read[$key] = HeldLifetime::ofPolicy($this->subject, $policy);
        }

        return $this->read[$key];
    }
}
