<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;

/**
 * Decides whether a policy document may be written (AUTHZ-6.2, AUTHZ-6.10).
 *
 * A document may be written only when it is a valid policy (its keys, version,
 * statements, operators and operands, and no two statements sharing a sid), is
 * within the configured limits, names every condition key in the key syntax,
 * and has every `actions` and `not_actions` pattern cover at least one action
 * of the bound action catalogue, so a policy written at runtime can only refer
 * to actions the code checks. With no actions declared, no document may be
 * written.
 *
 * The policy model's `document` attribute writes through here, and so does
 * every write of the policy service, and `authorization:policy:validate` checks
 * documents in files or the database with it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PolicyValidator
{
    /** @var string What a condition key may be: a name, then dot-separated segments. */
    public const string KEY_PATTERN = '/\A[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_-]+)*\z/';

    /** @var int The most characters a condition key may have. */
    public const int KEY_LENGTH = 128;

    /** @var string Why no document may be written when the catalogue declares no actions. */
    public const string NOTHING_DECLARED = 'No permissions are declared to check the policy\'s actions against; declare them in permission_enums or permission_providers.';

    /**
     * Create a new policy validator.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ActionCatalogue  $catalogue
     */
    public function __construct(

        /** The actions a policy may name. */
        private ActionCatalogue $catalogue,
    ) {}

    /**
     * Return the reasons the document cannot be written; none when it can.
     *
     * Every limit, condition-key and catalogue reason is given at once, but a
     * structural fault stops the check: when the document is not a valid
     * policy, only the first fault found and the limits it breaks are given.
     *
     * @param  mixed  $document
     * @return list<string>
     */
    public function errors(mixed $document): array
    {
        if (!\is_array($document)) {
            return ['Policy document must be a JSON object.'];
        }

        $errors = PolicyLimits::fromConfig()->violations($document);

        try {
            /** @var array<string, mixed> $document */
            $policy = Policy::fromArray($document);
        } catch (\InvalidArgumentException|\ValueError $exception) { // @phpstan-ignore catch.neverThrown
            // A ValueError is caught too, as a backstop: no part of a document
            // reaches a PHP function that refuses it outright, but were one to,
            // it would be reported rather than thrown.
            return [...$errors, $exception->getMessage()];
        }

        return [...$errors, ...self::keyErrors($policy), ...$this->catalogueErrors($policy)];
    }

    /**
     * Refuse a document that cannot be written, giving the reasons, joined by
     * `; ` into one sentence.
     *
     * @param  mixed  $document
     * @param  string  $name
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public function assertValid(mixed $document, string $name): void
    {
        $errors = $this->errors($document);

        if ($errors !== []) {
            throw new InvalidPolicyDocumentException(policyName: $name, reason: self::joined($errors));
        }
    }

    /**
     * Join the reasons a document cannot be written or read into one sentence,
     * separated by `; `.
     *
     * @param  non-empty-list<string>  $errors
     * @return string
     */
    public static function joined(array $errors): string
    {
        return \implode('; ', \array_map(static fn (string $error): string => \rtrim($error, '.'), $errors)) . '.';
    }

    /**
     * Return a reason for each condition key of each statement that is not in
     * the key syntax or is too long.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @return list<string>
     */
    private static function keyErrors(Policy $policy): array
    {
        $errors = [];

        foreach ($policy->statements as $index => $statement) {
            // The keys are checked for their syntax only, not yet against a
            // declared catalogue of context keys.
            foreach (\array_filter(self::keysOf($statement), static fn (string $key): bool => !self::isValidKey($key)) as $key) {
                $errors[] = "Policy statement #{$index} condition key '{$key}' must be letters, digits and '_', then any '.'-separated"
                    . ' segments that may also hold \'-\', and at most ' . self::KEY_LENGTH . ' characters.';
            }
        }

        return $errors;
    }

    /**
     * Return a reason for each `actions` and `not_actions` pattern that covers
     * no action of the catalogue, or the one reason no document may be written
     * when the catalogue declares no actions.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @return list<string>
     */
    private function catalogueErrors(Policy $policy): array
    {
        if (!$this->catalogue->covers('*')) {
            return [self::NOTHING_DECLARED];
        }

        $errors = [];

        foreach ($policy->statements as $index => $statement) {
            $field    = $statement->notActions === null ? 'actions' : 'not_actions';
            $patterns = $statement->notActions === null ? $statement->actions : $statement->notActions;

            foreach (\array_filter($patterns ?? [], fn (string $pattern): bool => !$this->catalogue->covers($pattern)) as $pattern) {
                $errors[] = "Policy statement #{$index} {$field} pattern '{$pattern}' matches no declared permission.";
            }
        }

        return $errors;
    }

    /**
     * Return every context key the statement's conditions test, once each.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @return list<string>
     */
    private static function keysOf(Statement $statement): array
    {
        $keys = [];

        // A statement's conditions have been checked to map operators to keyed
        // maps, so every entry is an array keyed by context key.
        /** @var array<string, array<string, mixed>> $conditions */
        $conditions = $statement->conditions;

        foreach ($conditions as $tests) {
            foreach (\array_keys($tests) as $key) {
                $keys[$key] = true;
            }
        }

        return \array_keys($keys);
    }

    /**
     * Determine whether the condition key is in the key syntax and not too
     * long.
     *
     * @param  string  $key
     * @return bool
     */
    private static function isValidKey(string $key): bool
    {
        return \strlen($key) <= self::KEY_LENGTH && \preg_match(self::KEY_PATTERN, $key) === 1;
    }
}
