<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\Refusal;

/**
 * Thrown when `whereAuthorized()` cannot prove that the rows it would keep are
 * exactly those `check()` allows (AUTHZ-10.2, N64): before the builder is
 * changed when it is called, and from the call that runs the query when it is
 * compiled again then. It never filters rows after loading them.
 *
 * A refusal is a developer or configuration fault, not a denial, so this is not
 * an `AuthorizationException`: Laravel renders it as a 500, never a 403. Its
 * message is an English diagnostic naming each refusal's reason and what it
 * could not compile, never a value, operand, pattern or tenant id, and is not
 * translated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class QueryScopeRefusedException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $action
     * @param  string  $resourceType
     * @param  list<\SineMacula\Laravel\Authorization\Query\Refusal>  $refusals
     */
    public function __construct(

        /** The action the query was to be scoped to. */
        public readonly string $action,

        /** The morph type of the model queried, or its class when it has none yet. */
        public readonly string $resourceType,

        /** Every reason the scope was refused. */
        public readonly array $refusals,
    ) {
        $described = \array_map(static fn (Refusal $refusal): string => $refusal->describe(), $refusals);

        parent::__construct("whereAuthorized('{$action}') cannot be compiled exactly for '{$resourceType}': " . \implode('; ', $described) . '.');
    }

    /**
     * Return the exception for a single refusal.
     *
     * @param  string  $action
     * @param  string  $resourceType
     * @param  \SineMacula\Laravel\Authorization\Query\Refusal  $refusal
     * @return self
     */
    public static function of(string $action, string $resourceType, Refusal $refusal): self
    {
        return new self($action, $resourceType, [$refusal]);
    }

    /**
     * Return the reason of every refusal, in order.
     *
     * @return list<\SineMacula\Laravel\Authorization\Query\Enums\RefusalReason>
     */
    public function reasons(): array
    {
        return \array_map(static fn (Refusal $refusal): RefusalReason => $refusal->reason, $this->refusals);
    }
}
