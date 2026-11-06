<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * The version tokens a resolution was built from, read as it runs.
 *
 * A resolution pins each grantee, role and policy before it reads that record's
 * data, so a write that commits while the resolution runs bumps a token after
 * it was pinned and the entry never holds. The cache pins the grantee before
 * the resolution starts; the resolution pins the roles and policies once it
 * knows which they are. Without a persistent store nothing is pinned and every
 * pin is a no-op.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ResolutionPins
{
    /** @var array<string, string> The token of each pinned version key. */
    private array $tokens = [];

    /** @var bool Whether every pin read its token. */
    private bool $complete = true;

    /**
     * Create a new set of pins.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\VersionedStore|null  $store
     */
    public function __construct(

        /** The store the tokens are read from; null when there is none. */
        private readonly ?VersionedStore $store = null,
    ) {}

    /**
     * Pin the grantee's version.
     *
     * @param  object  $grantee
     * @return void
     */
    public function grantee(object $grantee): void
    {
        if ($this->store === null) {
            return;
        }

        $this->pin($this->store, [$this->store->granteeKey($grantee)]);
    }

    /**
     * Pin the versions of the roles with the given keys.
     *
     * @param  list<string>  $roles
     * @return void
     */
    public function roles(array $roles): void
    {
        if ($this->store === null) {
            return;
        }

        $this->pin($this->store, \array_map($this->store->roleKey(...), $roles));
    }

    /**
     * Pin the versions of the tenant an entry is built in and of its ancestors,
     * so a change to the tree above it reaches the entry.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\TenantChain  $chain
     * @return void
     */
    public function tenants(TenantChain $chain): void
    {
        if ($this->store === null) {
            return;
        }

        $this->pin($this->store, \array_map($this->store->tenantKey(...), $chain->tenants));
    }

    /**
     * Pin the versions of the policies with the given keys.
     *
     * @param  list<string>  $policies
     * @return void
     */
    public function policies(array $policies): void
    {
        if ($this->store === null) {
            return;
        }

        $this->pin($this->store, \array_map($this->store->policyKey(...), $policies));
    }

    /**
     * Return the token of each pinned version key.
     *
     * @return array<string, string>
     */
    public function tokens(): array
    {
        return $this->tokens;
    }

    /**
     * Determine whether every pin read its token, so the resolution may be
     * stored.
     *
     * @return bool
     */
    public function isComplete(): bool
    {
        return $this->complete;
    }

    /**
     * Read and record the tokens of the keys, asking the store nothing for no
     * keys.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\VersionedStore  $store
     * @param  list<string>  $keys
     * @return void
     */
    private function pin(VersionedStore $store, array $keys): void
    {
        if ($keys === []) {
            return;
        }

        $tokens = $store->pin($keys);

        if ($tokens === null) {
            $this->complete = false;

            return;
        }

        $this->tokens = [...$this->tokens, ...$tokens];
    }
}
