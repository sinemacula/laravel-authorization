<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * The size limits of a policy document (AUTHZ-6.10), so a policy cannot be made
 * expensive to store or evaluate.
 *
 * A document may take up so many bytes, measured on its JSON encoding, and hold
 * so many statements; a statement may hold so many conditions, each key test of
 * each operator counting as one; and no action or resource pattern, nor any
 * string operand of a condition, may be longer than so many characters.
 *
 * The limits are read from `authorization.policies.limits`. They are enforced
 * when a document is written and again when a stored one is read, so lowering a
 * limit makes every stored document over it deny as an invalid policy until it
 * is fixed; `authorization:policy:validate --database` finds them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PolicyLimits
{
    /** @var list<string> The keys of `authorization.policies.limits`. */
    public const array KEYS = ['document_bytes', 'statements', 'conditions', 'pattern_length'];

    /** @var list<string> The statement keys that hold action or resource patterns. */
    private const array PATTERN_KEYS = ['actions', 'not_actions', 'resources', 'not_resources'];

    /**
     * Create a new set of policy limits.
     *
     * @param  int  $documentBytes
     * @param  int  $statements
     * @param  int  $conditions
     * @param  int  $patternLength
     */
    public function __construct(

        /** The most bytes the document's JSON encoding may take up. */
        public int $documentBytes = 65536,

        /** The most statements the document may hold. */
        public int $statements = 100,

        /** The most key tests one statement's conditions may hold. */
        public int $conditions = 50,

        /** The most characters any pattern or string operand may have. */
        public int $patternLength = 512,
    ) {}

    /**
     * Read the limits from `authorization.policies.limits`, taking the default
     * of each one that is not set.
     *
     * @return self
     */
    public static function fromConfig(): self
    {
        $limits = config('authorization.policies.limits', []);
        $limits = \is_array($limits) ? $limits : [];

        $defaults = new self;

        return new self(
            documentBytes: self::limitOf($limits, 'document_bytes', $defaults->documentBytes),
            statements: self::limitOf($limits, 'statements', $defaults->statements),
            conditions: self::limitOf($limits, 'conditions', $defaults->conditions),
            patternLength: self::limitOf($limits, 'pattern_length', $defaults->patternLength),
        );
    }

    /**
     * Return a fingerprint of the limits, which changes whenever any of them
     * does, so what was checked under one set of limits can be told apart from
     * what was checked under another.
     *
     * @return string
     */
    public function fingerprint(): string
    {
        return "{$this->documentBytes}.{$this->statements}.{$this->conditions}.{$this->patternLength}";
    }

    /**
     * Return every way the document is over the limits; none when it is within
     * them.
     *
     * The document need not be a valid policy: whatever of it can be measured
     * is measured, and the rest is left to the policy's own validation. A
     * document that cannot be encoded as JSON, such as one holding NaN, an
     * infinity or a string that is not valid UTF-8, cannot be measured or
     * stored, so that is a violation too.
     *
     * @param  array<array-key, mixed>  $document
     * @return list<string>
     */
    public function violations(array $document): array
    {
        $violations = [];
        $encoded    = \json_encode($document);

        if ($encoded === false) {
            $violations[] = 'Policy document cannot be encoded as JSON: ' . \json_last_error_msg() . '.';
        } elseif (\strlen($encoded) > $this->documentBytes) {
            $violations[] = 'Policy document is ' . \strlen($encoded) . " bytes, more than the {$this->documentBytes} allowed.";
        }

        $statements = \is_array($document['statements'] ?? null) ? $document['statements'] : [];

        if (\count($statements) > $this->statements) {
            $violations[] = 'Policy document has ' . \count($statements) . " statements, more than the {$this->statements} allowed.";
        }

        foreach (\array_filter($statements, \is_array(...)) as $index => $statement) {
            \array_push($violations, ...$this->statementViolations($index, $statement));
        }

        return $violations;
    }

    /**
     * Return every way one statement is over the limits.
     *
     * @param  int|string  $index
     * @param  array<array-key, mixed>  $statement
     * @return list<string>
     */
    private function statementViolations(int|string $index, array $statement): array
    {
        $violations = [];
        $conditions = \is_array($statement['conditions'] ?? null) ? $statement['conditions'] : [];
        $tests      = \array_sum(\array_map(static fn (mixed $tests): int => \is_array($tests) ? \count($tests) : 1, $conditions));

        if ($tests > $this->conditions) {
            $violations[] = "Policy statement #{$index} has {$tests} conditions, more than the {$this->conditions} allowed.";
        }

        $long = \array_filter(self::stringsOf($statement, $conditions), fn (string $value): bool => \mb_strlen($value) > $this->patternLength);

        if ($long !== []) {
            $violations[] = "Policy statement #{$index} has " . \count($long) . " patterns or operands longer than the {$this->patternLength} characters allowed.";
        }

        return $violations;
    }

    /**
     * Return every action and resource pattern of the statement, and every
     * string operand of its conditions, including each string in a list
     * operand.
     *
     * @param  array<array-key, mixed>  $statement
     * @param  array<array-key, mixed>  $conditions
     * @return array<int, string>
     */
    private static function stringsOf(array $statement, array $conditions): array
    {
        $values = [];

        foreach (self::PATTERN_KEYS as $key) {
            \array_push($values, ...self::listOf($statement[$key] ?? null));
        }

        foreach (\array_filter($conditions, \is_array(...)) as $tests) {
            foreach ($tests as $operand) {
                \array_push($values, ...(\is_array($operand) ? \array_values($operand) : [$operand]));
            }
        }

        return \array_filter($values, \is_string(...));
    }

    /**
     * Return the values of a list, or none for a value that is not an array.
     *
     * @param  mixed  $value
     * @return list<mixed>
     */
    private static function listOf(mixed $value): array
    {
        return \is_array($value) ? \array_values($value) : [];
    }

    /**
     * Return the configured limit, or the default when it is not a whole number
     * of at least one.
     *
     * @param  array<array-key, mixed>  $limits
     * @param  string  $key
     * @param  int  $default
     * @return int
     */
    private static function limitOf(array $limits, string $key, int $default): int
    {
        $limit = $limits[$key] ?? null;

        return \is_int($limit) && $limit >= 1 ? $limit : $default;
    }
}
