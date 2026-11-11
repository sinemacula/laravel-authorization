<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Usage\RouteMap;

/**
 * How the persistent tier of the resolution cache writes what a resolution
 * finds and reads it back: names as they are, and policies as their stored key,
 * their document and, for a resource policy, the resource it is attached to.
 * While grant usage is tracked, a grantee's permissions and policies are kept
 * under a kind of their own, with the routes of the grants behind them (see
 * `Usage\RouteMap`), so an entry kept without them, before tracking was turned
 * on, is never read for one.
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
    /** @var list<string> The kinds of entry kept with the routes of the grants behind them while grant usage is tracked. */
    private const array ROUTED = ['permissions', 'policies'];

    /** @var string The suffix of the kind a routed entry is kept under. */
    private const string ROUTED_SUFFIX = '-routed';

    /**
     * Return the kind an entry of the kind is kept under: its own, or, while
     * grant usage is tracked, a grantee's permissions' and policies' routed
     * kind.
     *
     * @param  string  $kind
     * @param  bool  $isTrackingUsage
     * @return string
     */
    public static function kindOf(string $kind, bool $isTrackingUsage): string
    {
        return $isTrackingUsage && \in_array($kind, self::ROUTED, true) ? $kind . self::ROUTED_SUFFIX : $kind;
    }

    /**
     * Determine whether entries of the kind are kept with their routes.
     *
     * @param  string  $kind
     * @return bool
     */
    public static function isRouted(string $kind): bool
    {
        return \str_ends_with($kind, self::ROUTED_SUFFIX);
    }

    /**
     * Return what the persistent tier holds of the routes behind an entry, as
     * the entry's `routes`, or nothing for none.
     *
     * @param  \SineMacula\Laravel\Authorization\Usage\RouteMap|null  $routes
     * @return array{routes?: array<string, mixed>}
     */
    public static function encodeRoutes(?RouteMap $routes): array
    {
        return $routes === null ? [] : ['routes' => $routes->toArray()];
    }

    /**
     * Read stored routes back, refusing anything that is not a route map.
     *
     * @param  mixed  $stored
     * @return \SineMacula\Laravel\Authorization\Usage\RouteMap
     *
     * @throws \UnexpectedValueException
     */
    public static function routes(mixed $stored): RouteMap
    {
        return RouteMap::fromArray($stored);
    }

    /**
     * Determine whether a stored value has the shape of an entry.
     *
     * @param  mixed  $entry
     * @return bool
     *
     * @phpstan-assert-if-true array{versions: non-empty-array<string, string>, value: array<mixed>, until: int, routes?: mixed} $entry
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
     * document, for a resource policy the resource it is attached to, and the
     * position each statement holds in the stored document, so a policy read
     * with some of its statements alone, its denies say, names each statement
     * at the same position once read back as when it was resolved.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @return array{id: string|null, document: array<string, mixed>, resource: string|null, positions: list<int>}
     */
    public static function encodePolicy(Policy $policy): array
    {
        return ['id' => $policy->id, 'document' => $policy->toArray(), 'resource' => $policy->resource, 'positions' => \array_keys($policy->statements)];
    }

    /**
     * Return what a resolution found as policies, refusing a resolution that
     * found anything else.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\Resolution<mixed>  $resolution
     * @return \SineMacula\Laravel\Authorization\Cache\Resolution<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \UnexpectedValueException
     */
    public static function policyResolution(Resolution $resolution): Resolution
    {
        $policies = [];

        foreach ($resolution->value as $policy) {
            if (!$policy instanceof Policy) {
                throw new \UnexpectedValueException('Resolved policy is not an evaluation policy.');
            }

            $policies[] = $policy;
        }

        return new Resolution($policies, $resolution->expiresIn, $resolution->stable, $resolution->routes);
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
     * Hydrate one stored policy back into an evaluation policy, each statement
     * at the position it was stored with, refusing one that is not a document
     * with its key. An entry kept without positions holds each statement at its
     * place in the document.
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
        $policy   = Policy::fromArray($document);

        return new Policy($policy->name, self::positioned($policy->statements, $entry['positions'] ?? null), $policy->version, $id, $resource);
    }

    /**
     * Return the statements read back, each at its stored position, or at its
     * place in the document when none were stored, refusing positions that are
     * not a distinct key of the policy's for each statement.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Statement>  $statements
     * @param  mixed  $positions
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Statement>
     *
     * @throws \UnexpectedValueException
     */
    private static function positioned(array $statements, mixed $positions): array
    {
        if ($positions === null) {
            return $statements;
        }

        $isOnePerStatement = \is_array($positions) && \array_is_list($positions) && \count($positions) === \count($statements);

        if (!$isOnePerStatement || \count(\array_unique($positions, \SORT_REGULAR)) !== \count($positions)) {
            throw new \UnexpectedValueException('Cached policy positions are not one distinct position for each statement.');
        }

        foreach ($positions as $position) {
            if (!\is_int($position) || $position < 0) {
                throw new \UnexpectedValueException('Cached policy position is not a statement\'s place in its document.');
            }
        }

        return \array_combine($positions, \array_values($statements));
    }
}
