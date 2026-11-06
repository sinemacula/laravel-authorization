<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;

/**
 * Decides whether a policy document may be written (AUTHZ-6.2, AUTHZ-6.10).
 *
 * A document may be written only when it is a valid policy (its keys, version,
 * statements, operators and operands, and no two statements sharing a sid), is
 * within the configured limits, reads only context keys the bound context key
 * catalogue declares (AUTHZ-8.1), and has every `actions` and `not_actions`
 * pattern cover at least one action of the bound action catalogue, so a policy
 * written at runtime can only refer to actions the code checks and context the
 * application supplies. With no actions declared, no document may be written.
 *
 * Every condition key must be declared, may be tested, and be of a type its
 * operator suits (`ContextKeyType`), and every `${…}` reference in an operand
 * or a resource pattern must name a declared key, `${subject.…}` and
 * `${resource.…}` included. A value of the wrong type is still undecidable at
 * evaluation, whatever the key declares.
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

    /** @var string How to declare a context key a policy reads. */
    public const string DECLARE_KEYS = 'declare it in authorization.context.keys or register it with the context key catalogue, '
        . 'or, under subject or resource, on an attribute provider.';

    /** @var string Why no document may be written when the catalogue declares no actions. */
    public const string NOTHING_DECLARED = 'No permissions are declared to check the policy\'s actions against; declare them in permission_enums or permission_providers.';

    /**
     * Create a new policy validator.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ActionCatalogue  $catalogue
     * @param  \SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue  $keys
     */
    public function __construct(

        /** The actions a policy may name. */
        private ActionCatalogue $catalogue,

        /** The context keys a policy may read. */
        private ContextKeyCatalogue $keys,
    ) {}

    /**
     * Return the reasons the document cannot be written; none when it can.
     *
     * Every limit, context key and catalogue reason is given at once, but a
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

        return [...$errors, ...$this->contextErrors($policy), ...$this->catalogueErrors($policy)];
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
     * Return a reason for each condition test and `${…}` reference of each
     * statement the key catalogue does not permit: a condition key not
     * declared, a condition on a key that may not be tested, an operator that
     * does not suit the key's type, and a reference to a key not declared.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @return list<string>
     */
    private function contextErrors(Policy $policy): array
    {
        $errors = [];

        foreach ($policy->statements as $index => $statement) {
            $errors = [...$errors, ...$this->statementContextErrors("Policy statement #{$index}", $statement)];
        }

        return \array_values(\array_unique($errors));
    }

    /**
     * Return a reason, after the prefix naming the statement, for each of its
     * condition tests and `${…}` references the key catalogue does not permit.
     *
     * @param  string  $prefix
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @return list<string>
     */
    private function statementContextErrors(string $prefix, Statement $statement): array
    {
        $errors   = [];
        $subjects = $statement->resources ?? $statement->notResources ?? [];

        // A statement's conditions have been checked to map operators to keyed
        // maps, so every entry is an array keyed by context key.
        /** @var array<string, array<string, mixed>> $conditions */
        $conditions = $statement->conditions;

        foreach ($conditions as $operator => $tests) {
            foreach ($tests as $key => $operand) {
                $errors[]   = $this->keys->permits($key, $operator) ? null : "{$prefix} " . $this->testError($key, $operator);
                $subjects[] = $operand;
            }
        }

        foreach (self::referencesOf($subjects) as $path) {
            $errors[] = $this->keys->permits($path) ? null : "{$prefix} reference '\${{$path}}' names no declared context key; " . self::DECLARE_KEYS;
        }

        return \array_values(\array_filter($errors, static fn (?string $error): bool => $error !== null));
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
     * Describe why a condition may not test the key with the operator: the key
     * is not declared, may not be tested, or is of a type the operator does not
     * suit.
     *
     * @param  string  $key
     * @param  string  $operator
     * @return string
     */
    private function testError(string $key, string $operator): string
    {
        $declared = $this->keys->find($key);

        if ($declared === null) {
            return "condition key '{$key}' is not a declared context key; " . self::DECLARE_KEYS;
        }

        if (!$declared->isTestable) {
            return "condition key '{$key}' may not be tested by a condition.";
        }

        $operators = \implode(', ', [...$declared->type->operators(), 'null']);

        return "condition operator '{$operator}' does not suit the {$declared->type->value} key '{$key}'; use one of {$operators}, or their _if_exists forms.";
    }

    /**
     * Return the path of every `${…}` reference in the string operands and
     * resource patterns, once each.
     *
     * @param  list<mixed>  $subjects
     * @return list<string>
     */
    private static function referencesOf(array $subjects): array
    {
        $paths = [];

        foreach (\array_filter($subjects, \is_string(...)) as $subject) {
            foreach (ContextInterpolator::references($subject) as $path) {
                $paths[$path] = $path;
            }
        }

        return \array_values($paths);
    }
}
