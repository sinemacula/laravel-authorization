<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Builds the `subject` and `resource` namespaces of a check (N29 to N32).
 *
 * Each holds the package's built-in keys and the attributes the provider
 * registered for its morph type declares:
 *
 * - `subject`: `id` (the subject's key, as a string), `type` (its morph class,
 *   or its class name) and, when the subject has a tenant, `tenant.type` and
 *   `tenant.id`, as `TenantScope` extracts them;
 * - `resource`: from the check's resource reference, `id` and `type` for a
 *   record, `type` alone for a type, neither for an opaque identifier (never
 *   read by splitting it), and `tenant.type` and `tenant.id` for a resource
 *   with a tenant. Only a record is given to its type's provider.
 *
 * A check with no subject, or no resource, has no such namespace. Each is built
 * the first time a statement of the check reads it, at most once, and never
 * kept for another check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AttributeNamespaces
{
    /**
     * Create a new attribute namespaces builder.
     *
     * @param  \SineMacula\Laravel\Authorization\Context\AttributeProviders|null  $providers
     */
    public function __construct(

        /** The providers registered by morph type; null for none, so only the built-ins are supplied. */
        private ?AttributeProviders $providers = null,
    ) {}

    /**
     * Return the builder of the `subject` namespace when the check has a
     * subject, and of the `resource` namespace when it names a resource.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @return array<string, \Closure(): array<array-key, mixed>>
     */
    public function builders(?Subject $subject, ?ResourceReference $resource): array
    {
        $builders = [];

        if ($subject !== null) {
            $builders[AttributeProviders::SUBJECT] = fn (): array => self::namespaced(AttributeProviders::SUBJECT, $this->subjectValues($subject));
        }

        if ($resource !== null) {
            $builders[AttributeProviders::RESOURCE] = fn (): array => self::namespaced(AttributeProviders::RESOURCE, $this->resourceValues($resource));
        }

        return $builders;
    }

    /**
     * Determine whether the subject's namespace depends on the request alone:
     * the subject's type has no attribute provider, or one marked
     * `ScopeInvariant`, so `whereAuthorized()` may read it once for a query.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return bool
     */
    public function isSubjectScopeInvariant(Subject $subject): bool
    {
        $class = $this->providers?->subjectProviderClass(self::typeOf($subject->subject));

        return $class === null || \is_subclass_of($class, ScopeInvariant::class);
    }

    /**
     * Return the subject's built-in keys and its provider's attributes.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    private function subjectValues(Subject $subject): array
    {
        $type     = self::typeOf($subject->subject);
        $builtIns = self::present(['id' => self::keyOf($subject->subject), 'type' => $type, 'tenant' => self::tenantOf($subject->tenant)]);

        return $builtIns + ($this->providers?->subjectValues($subject->subject, $type) ?? []);
    }

    /**
     * Return the resource's built-in keys and, for a record, its provider's
     * attributes.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @return array<string, mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     */
    private function resourceValues(ResourceReference $resource): array
    {
        $tenant   = $resource->tenant === null ? null : ['type' => $resource->tenant->type, 'id' => $resource->tenant->id];
        $builtIns = self::present(['id' => $resource->id, 'type' => $resource->type, 'tenant' => $tenant]);

        return $builtIns + ($this->providers?->resourceValues($resource) ?? []);
    }

    /**
     * Return the subject's key as a string, or null when it has none that is a
     * non-empty string or number.
     *
     * @param  object  $subject
     * @return string|null
     */
    private static function keyOf(object $subject): ?string
    {
        $key = \method_exists($subject, 'getKey') ? $subject->getKey() : null;

        return (\is_int($key) || \is_string($key)) && $key !== '' ? (string) $key : null;
    }

    /**
     * Return the subject's morph class, or its class name when it has none.
     *
     * @param  object  $subject
     * @return string
     */
    private static function typeOf(object $subject): string
    {
        $type = \method_exists($subject, 'getMorphClass') ? $subject->getMorphClass() : null;

        return \is_string($type) && $type !== '' ? $type : $subject::class;
    }

    /**
     * Return the tenant's morph type and key, or null for no tenant.
     *
     * @param  object|null  $tenant
     * @return array{type: string, id: string}|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    private static function tenantOf(?object $tenant): ?array
    {
        if ($tenant === null) {
            return null;
        }

        [$type, $id] = TenantScope::extractTenantPair($tenant);

        return ['type' => $type, 'id' => $id];
    }

    /**
     * Return the built-in keys that are present, leaving out each that is null.
     *
     * @param  array<string, mixed>  $values
     * @return array<string, mixed>
     */
    private static function present(array $values): array
    {
        return \array_filter($values, static fn (mixed $value): bool => $value !== null);
    }

    /**
     * Key a namespace's values by its name, leaving the namespace absent when
     * it has none.
     *
     * @param  string  $namespace
     * @param  array<string, mixed>  $values
     * @return array<string, array<string, mixed>>
     */
    private static function namespaced(string $namespace, array $values): array
    {
        return $values === [] ? [] : [$namespace => $values];
    }
}
