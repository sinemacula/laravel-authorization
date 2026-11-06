<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use SineMacula\Laravel\Authorization\Evaluation\Policy;

/**
 * How the persistent tier of the resolution cache writes what a resolution
 * finds and reads it back: names as they are, and policies as their stored key,
 * their document and, for a resource policy, the resource it is attached to.
 *
 * Whatever is read back is checked against the shape it was written in, and an
 * entry that does not hold to it is refused with `UnexpectedValueException`, so
 * the cache discards it and resolves afresh rather than decide from it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResolutionCodec
{
    /**
     * Determine whether a stored value has the shape of an entry.
     *
     * @param  mixed  $entry
     * @return bool
     *
     * @phpstan-assert-if-true array{versions: non-empty-array<string, string>, value: array<mixed>, until: int} $entry
     */
    public static function isEntry(mixed $entry): bool
    {
        if (!\is_array($entry) || !\is_int($entry['until'] ?? null)) {
            return false;
        }

        return \is_array($entry['value'] ?? null) && \is_array($entry['versions'] ?? null) && $entry['versions'] !== [];
    }

    /**
     * Read stored names back, refusing anything that is not a list of names.
     *
     * @param  array<mixed>  $stored
     * @return list<string>
     *
     * @throws \UnexpectedValueException
     */
    public static function names(array $stored): array
    {
        foreach ($stored as $name) {
            if (!\is_string($name)) {
                throw new \UnexpectedValueException('Cached name is not a string.');
            }
        }

        /** @var list<string> */
        return $stored;
    }

    /**
     * Return what the persistent tier holds of a policy: its stored key, its
     * document and, for a resource policy, the resource it is attached to.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @return array{id: string|null, document: array<string, mixed>, resource: string|null}
     */
    public static function encodePolicy(Policy $policy): array
    {
        return ['id' => $policy->id, 'document' => $policy->toArray(), 'resource' => $policy->resource];
    }

    /**
     * Hydrate stored policy documents back into evaluation policies, each with
     * its stored key and, for a resource policy, the resource it is attached
     * to.
     *
     * @param  array<mixed>  $stored
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \UnexpectedValueException
     */
    public static function policies(array $stored): array
    {
        $policies = [];

        foreach ($stored as $entry) {
            $policies[] = self::policyOf($entry);
        }

        return $policies;
    }

    /**
     * Hydrate one stored policy back into an evaluation policy, refusing one
     * that is not a document with its key.
     *
     * @param  mixed  $entry
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     *
     * @throws \UnexpectedValueException
     */
    private static function policyOf(mixed $entry): Policy
    {
        $id       = \is_array($entry) ? $entry['id']       ?? null : null;
        $resource = \is_array($entry) ? $entry['resource'] ?? null : null;

        if (!\is_array($entry) || !\is_array($entry['document'] ?? null) || ($id !== null && !\is_string($id)) || ($resource !== null && !\is_string($resource))) {
            throw new \UnexpectedValueException('Cached policy entry is not a policy document with its key.');
        }

        /** @var array<string, mixed> $document */
        $document = $entry['document'];

        return Policy::fromArray($document)->withId($id)->withResource($resource);
    }
}
