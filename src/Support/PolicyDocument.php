<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Models\Policy;

/**
 * Reads a stored policy document: decodes it, names it after the stored policy,
 * and hydrates it into an evaluation policy.
 *
 * The policy model's `document` attribute validates a write through here, and
 * the grant resolver hydrates every attached policy through `hydrate()`, so a
 * document is read the same way going in and coming out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PolicyDocument
{
    /** @var string The name a policy without one is reported under. */
    public const string UNNAMED = '[unnamed]';

    /**
     * Hydrate the stored policy into an evaluation policy, under the stored
     * policy's name whatever the document says.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public static function hydrate(Policy $policy): EvaluationPolicy
    {
        $name     = self::nameOf($policy->getAttribute('name'));
        $document = self::named(self::decode($policy->getAttribute('document'), $name), $policy->getAttribute('name'), true);

        try {
            return EvaluationPolicy::fromArray($document);
        } catch (\Throwable $exception) {
            throw new InvalidPolicyDocumentException(policyName: $name, reason: $exception->getMessage(), previous: $exception);
        }
    }

    /**
     * Decode a raw document into an associative array: an array as it is, a
     * JSON object or array string decoded.
     *
     * @param  mixed  $value
     * @param  string  $name
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public static function decode(mixed $value, string $name): array
    {
        $decoded = \is_string($value) && $value !== '' ? \json_decode($value, true) : $value;

        if (!\is_array($decoded)) {
            throw new InvalidPolicyDocumentException(policyName: $name, reason: 'policy document must be a JSON object or array.');
        }

        /** @var array<string, mixed> */
        return $decoded;
    }

    /**
     * Give the document the policy's name, when the policy has one: always,
     * when overriding, else only when the document names none.
     *
     * @param  array<string, mixed>  $document
     * @param  mixed  $name
     * @param  bool  $override
     * @return array<string, mixed>
     */
    public static function named(array $document, mixed $name, bool $override = false): array
    {
        $named = \is_string($document['name'] ?? null) && $document['name'] !== '';

        if (\is_string($name) && $name !== '' && ($override || !$named)) {
            $document['name'] = $name;
        }

        return $document;
    }

    /**
     * Return the name a policy is reported under: its own, or the placeholder
     * for one without a name.
     *
     * @param  mixed  $name
     * @return string
     */
    public static function nameOf(mixed $name): string
    {
        return \is_string($name) && $name !== '' ? $name : self::UNNAMED;
    }
}
