<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions\Evaluation;

/**
 * Policy.
 *
 * An immutable value object representing a named collection of
 * policy statements. Policies are evaluated together during
 * IAM-style authorization checks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final readonly class Policy
{
    /**
     * Create a new policy instance.
     *
     * @param  string  $name
     * @param  array<int, \SineMacula\Laravel\Iam\Permissions\Evaluation\Statement>  $statements
     */
    public function __construct(
        public string $name,
        public array $statements,
    ) {}

    /**
     * Create a policy from an associative array.
     *
     * @param  array{name: string, statements: array<int, array<string, mixed>>}  $data
     * @return self
     */
    public static function fromArray(array $data): self
    {
        $statements = array_map(
            static fn (array $statement): Statement => Statement::fromArray($statement),
            $data['statements'],
        );

        return new self(
            name: $data['name'],
            statements: $statements,
        );
    }
}
