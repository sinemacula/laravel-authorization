<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Context\ContextKey;
use SineMacula\Laravel\Authorization\Enums\ContextKeyType;

/**
 * Context key catalogue contract (N25, AUTHZ-8.1).
 *
 * The context keys a policy may read: each a full dot path, its namespace
 * first, with a type that decides the operators a condition may test it with,
 * and whether a condition may test it at all. A policy naming a key the
 * catalogue does not declare is refused on write, and so is a condition on an
 * untestable key or with an operator that does not suit the key's type.
 *
 * The shipped default declares the package's own keys (`authentication.guard`,
 * `authentication.user_id`, `authentication.user_type`, `request.ip`,
 * `request.method`, `request.route` and `environment.time`) and those of
 * `authorization.context.keys`; an application or sibling package registers its
 * own namespace and keys from a service provider. Keys of the `input`
 * namespace, which holds the values the caller passes, are declared like any
 * other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ContextKeyCatalogue
{
    /**
     * Declare one key by its full dot path.
     *
     * Declaring a key again as it was declared changes nothing; declaring it
     * with another type or testability is refused, so one declaration never
     * silently changes what another relies on.
     *
     * @param  string  $path
     * @param  \SineMacula\Laravel\Authorization\Enums\ContextKeyType  $type
     * @param  bool  $isTestable
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function declare(string $path, ContextKeyType $type, bool $isTestable = true): void;

    /**
     * Register a namespace's keys, each a dot path within the namespace mapped
     * to its type, as `authorization.context.keys` lists them: `['tenant' =>
     * ['plan' => 'string']]` declares `tenant.plan`. Every key registered this
     * way may be tested.
     *
     * @param  string  $namespace
     * @param  array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>  $keys
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function register(string $namespace, array $keys): void;

    /**
     * Determine whether a policy may read the key at the dot path: it is
     * declared and, when a condition tests it with the operator (written as in
     * a policy document, such as `ip_in_if_exists`), it may be tested and the
     * operator suits its type. With no operator the key is only read, as a
     * `${…}` reference reads it, and need only be declared.
     *
     * @param  string  $path
     * @param  string|null  $operator
     * @return bool
     */
    public function permits(string $path, ?string $operator = null): bool;

    /**
     * Return the declared key at the dot path, or null when none is declared.
     *
     * @param  string  $path
     * @return \SineMacula\Laravel\Authorization\Context\ContextKey|null
     */
    public function find(string $path): ?ContextKey;

    /**
     * Return every declared key, by its dot path, in order of path.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Context\ContextKey>
     */
    public function keys(): array;

    /**
     * Return every namespace a declared key belongs to, in order of name.
     *
     * @return list<string>
     */
    public function namespaces(): array;
}
