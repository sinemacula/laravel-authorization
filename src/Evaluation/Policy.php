<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * Immutable policy value object.
 *
 * Represents a named collection of statements that travel together through the
 * evaluator. Policy documents are versioned so future schema changes can be
 * detected without a database migration; v1 documents default to `version = 1`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Policy
{
    /** @var int Current policy-document schema version. */
    public const int CURRENT_VERSION = 1;

    /**
     * Create a new policy instance.
     *
     * @param  string  $name
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Statement>  $statements
     * @param  int  $version
     */
    public function __construct(

        /** Human-readable policy name used in traces and audit logs. */
        public string $name,

        /** Ordered list of statements that make up the policy. */
        public array $statements,

        /** Document schema version; defaults to the current constant. */
        public int $version = self::CURRENT_VERSION,
    ) {}

    /**
     * Hydrate a policy from its array representation.
     *
     * @param  array<string, mixed>  $data
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromArray(array $data): self
    {
        if (!isset($data['name']) || !\is_string($data['name']) || $data['name'] === '') {
            throw new \InvalidArgumentException('Policy document requires a non-empty name.');
        }

        if (!isset($data['statements']) || !\is_array($data['statements'])) {
            throw new \InvalidArgumentException('Policy document requires a list of statements.');
        }

        $version = self::versionFrom($data);

        $statements = \array_values(\array_map(static function (mixed $statement): Statement {
            if (!\is_array($statement)) {
                throw new \InvalidArgumentException('Policy statements must be associative arrays.');
            }

            return Statement::fromArray($statement);
        }, $data['statements']));

        return new self(
            name: $data['name'],
            statements: $statements,
            version: $version,
        );
    }

    /**
     * Serialise the policy for persistence.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'version'    => $this->version,
            'name'       => $this->name,
            'statements' => \array_map(
                static fn (Statement $statement): array => $statement->toArray(),
                $this->statements,
            ),
        ];
    }

    /**
     * Extract and validate the document version, defaulting to the current
     * version when absent.
     *
     * @param  array<string, mixed>  $data
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private static function versionFrom(array $data): int
    {
        if (!isset($data['version'])) {
            return self::CURRENT_VERSION;
        }

        if (!\is_int($data['version']) || $data['version'] < 1) {
            throw new \InvalidArgumentException('Policy document version must be a positive integer.');
        }

        return $data['version'];
    }
}
