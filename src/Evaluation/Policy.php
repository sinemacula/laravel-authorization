<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;

/**
 * Immutable policy value object.
 *
 * Represents a named collection of statements that travel together through the
 * evaluator. Policy documents are versioned so future schema changes can be
 * detected without a database migration; a document without a version is
 * version 1, and a version this package does not know is refused, as is any key
 * other than `version`, `name` and `statements`, and two statements that share
 * a `sid`.
 *
 * A policy attached to a resource or a resource type (AUTHZ-7.3) carries the
 * resource it is attached to, which is not part of its document: its allows
 * apply only to the subjects their `principals` name, and its denies to
 * everyone checking the resource.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Policy
{
    /** @var int Current policy-document schema version. */
    public const int CURRENT_VERSION = 1;

    /** @var list<string> The keys a policy document may carry. */
    private const array KEYS = ['version', 'name', 'statements'];

    /**
     * Create a new policy instance.
     *
     * @param  string  $name
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Statement>  $statements
     * @param  int  $version
     * @param  string|null  $id
     * @param  string|null  $resource
     */
    public function __construct(

        /** Human-readable policy name used in traces and audit logs. */
        public string $name,

        /** Ordered list of statements that make up the policy. */
        public array $statements,

        /** Document schema version; defaults to the current constant. */
        public int $version = self::CURRENT_VERSION,

        /** The stored policy's key, which tells apart policies of one name; null for one built in code. */
        public ?string $id = null,

        /** The resource a resource policy is attached to, `type:id` or `type:*` for its type; null for any other policy. */
        public ?string $resource = null,
    ) {}

    /**
     * Return the policy as the stored policy with the given key.
     *
     * @param  string|null  $id
     * @return self
     */
    public function withId(?string $id): self
    {
        return new self($this->name, $this->statements, $this->version, $id, $this->resource);
    }

    /**
     * Return the policy as a resource policy attached to the resource, named by
     * its identifier (`type:id`, or `type:*` for the whole type), or as a
     * policy attached any other way when it is null.
     *
     * @param  string|null  $resource
     * @return self
     */
    public function withResource(?string $resource): self
    {
        return new self($this->name, $this->statements, $this->version, $this->id, $resource);
    }

    /**
     * Return the policy with its deny statements alone, at the positions they
     * hold in its document: what counts of a policy whose allows apply nowhere,
     * as an attachment naming half a tenant, or a deny attached in a tenant a
     * check is decided outside of.
     *
     * @return self
     */
    public function denies(): self
    {
        $denies = \array_filter($this->statements, static fn (Statement $statement): bool => $statement->effect === PolicyEffect::DENY);

        return new self($this->name, $denies, $this->version, $this->id, $this->resource);
    }

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
        $unknown = \array_diff(\array_keys($data), self::KEYS);

        if ($unknown !== []) {
            throw new \InvalidArgumentException('Policy document has unknown keys: ' . \implode(', ', $unknown) . '.');
        }

        if (!isset($data['name']) || !\is_string($data['name']) || $data['name'] === '') {
            throw new \InvalidArgumentException('Policy document requires a non-empty name.');
        }

        if (!isset($data['statements']) || !\is_array($data['statements'])) {
            throw new \InvalidArgumentException('Policy document requires a list of statements.');
        }

        $version = self::versionFrom($data);

        $statements = [];

        foreach ($data['statements'] as $statement) {
            if (!\is_array($statement)) {
                throw new \InvalidArgumentException('Policy statements must be associative arrays.');
            }

            $statements[] = Statement::fromArray($statement);
        }

        self::assertUniqueSids($statements);

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
     * Refuse statements that share a sid, naming each sid used more than once.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Statement>  $statements
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertUniqueSids(array $statements): void
    {
        $sids       = \array_filter(\array_map(static fn (Statement $statement): ?string => $statement->sid, $statements), static fn (?string $sid): bool => $sid !== null);
        $duplicates = \array_unique(\array_diff_key($sids, \array_unique($sids)));

        if ($duplicates !== []) {
            throw new \InvalidArgumentException('Policy document has statements sharing a sid: ' . \implode(', ', $duplicates) . '.');
        }
    }

    /**
     * Extract and validate the document version, defaulting to the current
     * version when absent and refusing a version this package does not know.
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

        if ($data['version'] !== self::CURRENT_VERSION) {
            throw new \InvalidArgumentException("Policy document version {$data['version']} is not supported.");
        }

        return $data['version'];
    }
}
