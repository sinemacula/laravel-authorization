<?php

declare(strict_types = 1);

namespace Tests\Fixtures\GrantScope;

use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Support\IdentityPrincipals;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * An identity directory listing the principals a test gives each identity, as
 * complete or incomplete as the test says, and counting how often it is asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ListedIdentityDirectory implements IdentityDirectory
{
    /** @var int How many times the directory was asked. */
    public int $asked = 0;

    /**
     * Create a new directory.
     *
     * @param  array<string, list<\SineMacula\Laravel\Authorization\Support\Reference>>  $principals
     * @param  bool  $isComplete
     */
    public function __construct(

        /** The principals of each identity, keyed by `key()`. */
        private readonly array $principals = [],

        /** Whether each list is complete. */
        private readonly bool $isComplete = true,
    ) {}

    /**
     * Return the key the principals of the identity are listed under.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $identity
     * @return string
     */
    public static function key(Reference $identity): string
    {
        return $identity->type . "\0" . $identity->id;
    }

    /**
     * Return the principals listed for the identity, none for one not listed.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $identity
     * @return \SineMacula\Laravel\Authorization\Support\IdentityPrincipals
     */
    #[\Override]
    public function principalsOf(Reference $identity): IdentityPrincipals
    {
        $this->asked++;

        return new IdentityPrincipals($this->principals[self::key($identity)] ?? [], $this->isComplete);
    }
}
