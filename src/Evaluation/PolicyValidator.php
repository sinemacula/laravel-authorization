<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Context\AssuranceKeys;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;

/**
 * Decides whether a policy document may be written (AUTHZ-6.2, AUTHZ-6.10).
 *
 * A document may be written only when it is a valid policy (its keys, version,
 * statements, operators and operands, and no two statements sharing a sid), is
 * within the configured limits, reads only context keys the bound context key
 * catalogue declares (AUTHZ-8.1), and has every `actions` and `not_actions`
 * pattern cover at least one action of the bound action catalogue, or one of
 * the package's own permissions (see `PackagePermissions`), which the catalogue
 * never holds, so a policy written at runtime can only refer to actions the
 * code checks and context the application supplies. With no actions declared by
 * the application, a document whose patterns need any action but the package's
 * own is refused with the one reason that nothing is declared, and one naming
 * only the package's own may still be written.
 *
 * Every condition key must be declared, may be tested, and be of a type its
 * operator suits (`ContextKeyType`), and every `${…}` reference in an operand
 * or a resource pattern must name a declared key, `${subject.…}` and
 * `${resource.…}` included. A value of the wrong type is still undecidable at
 * evaluation, whatever the key declares.
 *
 * An `authentication_requirement` test reads no context key, so the catalogue
 * is not asked about its key `authentication`. An assurance key of the
 * authentication context (see `AssuranceKeys`) may never be tested or read
 * through a `${…}` reference, whatever the catalogue declares (AUTHZ-8.9, N37):
 * the reason points at `authentication_requirement`.
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

    /** @var string Why a document needing any action but the package's own may not be written when the catalogue declares no actions. */
    public const string NOTHING_DECLARED = 'No permissions are declared to check the policy\'s actions against; declare them in permission_enums or permission_providers.';

    /**
     * Create a new policy validator.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ActionCatalogue  $catalogue
     * @param  \SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue  $keys
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthenticationContext|null  $authentication
     */
    public function __construct(

        /** The actions a policy may name. */
        private ActionCatalogue $catalogue,

        /** The context keys a policy may read. */
        private ContextKeyCatalogue $keys,

        /** The authentication context, whose contributed namespaces hold assurance keys too; null for `authentication` alone. */
        private ?AuthenticationContext $authentication = null,
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
        $errors     = [];
        $namespaces = $this->authentication?->namespaces() ?? [];

        foreach ($policy->statements as $index => $statement) {
            $errors = [...$errors, ...$this->statementContextErrors("Policy statement #{$index}", $statement, $namespaces)];
        }

        return \array_values(\array_unique($errors));
    }

    /**
     * Return a reason, after the prefix naming the statement, for each of its
     * condition tests and `${…}` references the key catalogue does not permit,
     * or that names an assurance key of `authentication` or of one of the
     * namespaces the authentication context contributes.
     *
     * @param  string  $prefix
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  list<string>  $namespaces
     * @return list<string>
     */
    private function statementContextErrors(string $prefix, Statement $statement, array $namespaces): array
    {
        $errors   = [];
        $subjects = $statement->resources ?? $statement->notResources ?? [];

        // A statement's conditions have been checked to map operators to keyed
        // maps, so every entry is an array keyed by context key. A requirement
        // reads no context key, and its operand holds no reference.
        /** @var array<string, array<string, mixed>> $conditions */
        $conditions = \array_diff_key($statement->conditions, [AuthenticationRequirement::OPERATOR => true]);

        foreach ($conditions as $operator => $tests) {
            foreach ($tests as $key => $operand) {
                $errors[]   = self::prefixed($prefix, $this->keyError($key, $operator, $namespaces));
                $subjects[] = $operand;
            }
        }

        foreach (self::referencesOf($subjects) as $path) {
            $errors[] = self::prefixed($prefix, $this->referenceError($path, $namespaces));
        }

        return \array_values(\array_filter($errors, static fn (?string $error): bool => $error !== null));
    }

    /**
     * Return the reason after the prefix naming the statement, or null when
     * there is no reason.
     *
     * @param  string  $prefix
     * @param  string|null  $error
     * @return string|null
     */
    private static function prefixed(string $prefix, ?string $error): ?string
    {
        return $error === null ? null : "{$prefix} {$error}";
    }

    /**
     * Describe why a condition may not test the key with the operator, or
     * return null when it may.
     *
     * @param  string  $key
     * @param  string  $operator
     * @param  list<string>  $namespaces
     * @return string|null
     */
    private function keyError(string $key, string $operator, array $namespaces): ?string
    {
        return match (true) {
            AssuranceKeys::isAssuranceKey($key, $namespaces) => "condition key '{$key}' " . AssuranceKeys::REASON,
            $this->keys->permits($key, $operator)            => null,
            default                                          => $this->testError($key, $operator),
        };
    }

    /**
     * Describe why a `${…}` reference may not read the key at the path, or
     * return null when it may.
     *
     * @param  string  $path
     * @param  list<string>  $namespaces
     * @return string|null
     */
    private function referenceError(string $path, array $namespaces): ?string
    {
        return match (true) {
            AssuranceKeys::isAssuranceKey($path, $namespaces) => "reference '\${{$path}}' names '{$path}', which " . AssuranceKeys::REASON,
            $this->keys->permits($path)                       => null,
            default                                           => "reference '\${{$path}}' names no declared context key; " . self::DECLARE_KEYS,
        };
    }

    /**
     * Return a reason for each `actions` and `not_actions` pattern that covers
     * neither a permission of the package's own nor an action of the catalogue,
     * or, when there is one and the catalogue declares no actions, the one
     * reason that nothing is declared.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @return list<string>
     */
    private function catalogueErrors(Policy $policy): array
    {
        $errors = [];

        foreach ($policy->statements as $index => $statement) {
            $field    = $statement->notActions === null ? 'actions' : 'not_actions';
            $patterns = $statement->notActions === null ? $statement->actions : $statement->notActions;

            foreach (\array_filter($patterns ?? [], $this->isUndeclared(...)) as $pattern) {
                $errors[] = "Policy statement #{$index} {$field} pattern '{$pattern}' matches no declared permission.";
            }
        }

        return $errors !== [] && !$this->catalogue->covers('*') ? [self::NOTHING_DECLARED] : $errors;
    }

    /**
     * Determine whether the action pattern covers no permission of the
     * package's own and no action of the catalogue.
     *
     * @param  string  $pattern
     * @return bool
     */
    private function isUndeclared(string $pattern): bool
    {
        return !PackagePermissions::covers($pattern) && !$this->catalogue->covers($pattern);
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
