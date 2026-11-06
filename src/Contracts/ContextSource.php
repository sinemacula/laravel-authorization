<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Context source contract (N26, AUTHZ-8.6).
 *
 * Supplies one namespace of the context an application adds, such as `tenant`
 * or `device`, listed in `authorization.context.sources` and resolved from the
 * container. Its values are read the first time a statement of a check reads
 * the namespace, and at most once for the check; a namespace no statement reads
 * is never built. The namespace's keys are declared in the context key
 * catalogue like any other.
 *
 * A source may not claim a reserved namespace: the trusted ones
 * (`authentication`, `request`, `environment`) are replaced only by rebinding
 * their own contracts, `input` holds what the caller passes, and `subject` and
 * `resource` hold the check's subject and resource, from their built-in keys
 * and attribute providers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ContextSource
{
    /** @var list<string> The namespaces of the check's subject and resource: their keys are the package's built-ins and those attribute providers declare, never a source's. */
    public const array ATTRIBUTE_NAMESPACES = ['subject', 'resource'];

    /** @var list<string> The namespaces no source may claim. */
    public const array RESERVED_NAMESPACES = ['authentication', 'request', 'environment', 'input', ...self::ATTRIBUTE_NAMESPACES];

    /**
     * Return the namespace the source supplies.
     *
     * @return string
     */
    public function namespace(): string;

    /**
     * Return the namespace's values for the current check, nested by key, so
     * `['plan' => ['tier' => 'pro']]` supplies `<namespace>.plan.tier`. A key
     * left out is missing; an empty array leaves the namespace absent.
     *
     * @return array<string, mixed>
     */
    public function values(): array;
}
