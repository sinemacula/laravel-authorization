<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Query\Refusal;

/**
 * Thrown when an authorized scope, `whereAuthorized()` or the model-level
 * `AuthorizedScope`, cannot prove that the rows it would keep are exactly those
 * `check()` allows (AUTHZ-10.2, N64): from `whereAuthorized()` before the
 * builder is changed, and from the call that runs the query when either is
 * compiled then. It never filters rows after loading them.
 *
 * A refusal is a developer or configuration fault, not a denial, so this is not
 * an `AuthorizationException`: Laravel renders it as a 500, never a 403. Its
 * message is an English diagnostic naming each refusal's reason and what it
 * could not compile, never a value, operand, pattern or tenant id, and is not
 * translated. A refusal for the policies attached to the type's records names
 * none of them, so the message stays one line however many there are.
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

        /** The morph type of the model queried, through the morph map when it has one. */
        public readonly string $resourceType,

        /** Every reason the scope was refused. */
        public readonly array $refusals,
    ) {
        $described = \array_map(static fn (Refusal $refusal): string => $refusal->describe(), $refusals);

        parent::__construct("The authorized scope for '{$action}' cannot be compiled exactly for '{$resourceType}': " . \implode('; ', $described) . '.');
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
