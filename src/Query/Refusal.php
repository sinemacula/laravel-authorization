<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;

/**
 * One reason an authorized scope refused to scope a query, naming what it could
 * not compile: the policy and statement, the condition key, namespace, column
 * or seam class, and a fixed phrase. It never carries an operand, a pattern, a
 * context value, a row's value or a tenant id (N64).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Refusal
{
    /**
     * Create a new refusal.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason  $reason
     * @param  string|null  $policy
     * @param  string|null  $statement
     * @param  string|null  $key
     * @param  string|null  $detail
     */
    public function __construct(

        /** Why the scope was refused. */
        public RefusalReason $reason,

        /** The policy, as `name[key]`, or null when the refusal is not about one. */
        public ?string $policy = null,

        /** The statement, as its reference reads, or null when the refusal is not about one. */
        public ?string $statement = null,

        /** The condition key, namespace, column or seam class, or null. */
        public ?string $key = null,

        /** A fixed phrase saying more, or null. */
        public ?string $detail = null,
    ) {}

    /**
     * Return a refusal about a statement, naming its policy and itself.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason  $reason
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $statement
     * @param  string|null  $key
     * @return self
     */
    public static function ofStatement(RefusalReason $reason, StatementReference $statement, ?string $key = null): self
    {
        $policy = $statement->policy . ($statement->policyId === null ? '' : "[{$statement->policyId}]");

        return new self($reason, $policy, $statement->toString(), $key);
    }

    /**
     * Return the refusal as one line of English: its reason, then what it
     * names.
     *
     * @return string
     */
    public function describe(): string
    {
        $parts = \array_filter([
            'statement' => $this->statement ?? $this->policy,
            'key'       => $this->key,
            'detail'    => $this->detail,
        ], static fn (?string $part): bool => $part !== null);

        $named = [];

        foreach ($parts as $label => $part) {
            $named[] = "{$label} {$part}";
        }

        return $this->reason->value . ($named === [] ? '' : ' (' . \implode(', ', $named) . ')');
    }
}
