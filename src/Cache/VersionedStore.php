<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The persistent tier of the resolution cache: entries, and the version tokens
 * that decide whether an entry still holds.
 *
 * Every grantee, role, policy and tenant has a version token, a random string
 * that a write bumps by replacing it, and the policies attached to roles share
 * one more, as do the policies attached to the resources of each type, every
 * resource policy entry, every entry of a grantee's permission boundaries and
 * every entry of the guardrails. An entry records the tokens of everything it
 * was built from, and holds only while every one of them is unchanged, so a
 * write invalidates exactly the entries it affects on any store, with or
 * without tags. A token is random rather than a counter, so a token the store
 * evicted and created again can never match an entry recorded before.
 *
 * A store that fails is never fatal to a check: the read or write is skipped,
 * the failure is written to the package's log channel once, and the store is
 * not used again by this instance, which lasts one request or job, so checks
 * fall back to the database. A bump that runs inside a write's transaction is
 * the exception: its failure is thrown, so the write rolls back rather than
 * leave a stale entry that still allows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class VersionedStore
{
    /** @var bool Whether the store has failed in this request or job. */
    private bool $failed = false;

    /**
     * Create a new versioned store instance.
     *
     * @param  \Illuminate\Contracts\Cache\Repository  $store
     * @param  string  $prefix
     */
    public function __construct(

        /** The cache store the entries and tokens are kept in. */
        private readonly CacheRepository $store,

        /** Namespace prefix for every key written here. */
        private readonly string $prefix,
    ) {}

    /**
     * Return the key of the grantee's version token.
     *
     * @param  object  $grantee
     * @return string
     */
    public function granteeKey(object $grantee): string
    {
        return "{$this->prefix}:version:grantee:" . PrincipalCacheKey::for($grantee);
    }

    /**
     * Return the key of the role's version token.
     *
     * @param  string  $role
     * @return string
     */
    public function roleKey(string $role): string
    {
        return "{$this->prefix}:version:role:{$role}";
    }

    /**
     * Return the key of the policy's version token.
     *
     * @param  string  $policy
     * @return string
     */
    public function policyKey(string $policy): string
    {
        return "{$this->prefix}:version:policy:{$policy}";
    }

    /**
     * Return the key of the one version token every policy attachment to a role
     * shares, which every entry of an identity's policies records before it
     * reads whether any role holds a policy, and every attachment, detachment
     * or expiry change of a role's policy bumps.
     *
     * @return string
     */
    public function rolePoliciesKey(): string
    {
        return "{$this->prefix}:version:role-policies";
    }

    /**
     * Return the key of the version token the policies attached to resources of
     * the type share, which an attachment to the type or to any of its records
     * bumps; or, with no type, of the one token every resource policy entry
     * shares, which a change to any policy or its deletion bumps. Every entry
     * of a resource's policies records both before it reads the attachments.
     *
     * @param  string|null  $type
     * @return string
     */
    public function resourcePoliciesKey(?string $type = null): string
    {
        return "{$this->prefix}:version:resource-policies" . ($type === null ? '' : ':' . $type);
    }

    /**
     * Return the key of the one version token every entry of a grantee's
     * permission boundaries shares, which a change to any policy or its
     * deletion bumps. Every such entry records it before it reads the
     * boundaries and their documents in one query; setting or removing a
     * boundary bumps the grantee.
     *
     * @return string
     */
    public function boundariesKey(): string
    {
        return "{$this->prefix}:version:boundaries";
    }

    /**
     * Return the key of the one version token every entry of the guardrails
     * that apply in a scope shares, which setting or removing any guardrail,
     * and a change to any policy or its deletion, bumps. Every such entry
     * records it before it reads the guardrails and their documents in one
     * query.
     *
     * @return string
     */
    public function guardrailsKey(): string
    {
        return "{$this->prefix}:version:guardrails";
    }

    /**
     * Return the key of the tenant's version token, which every entry built in
     * the tenant or below it records.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return string
     */
    public function tenantKey(Reference $tenant): string
    {
        return "{$this->prefix}:version:tenant:{$tenant->type}:{$tenant->id}";
    }

    /**
     * Return the value stored at the key, or null when there is none or the
     * store fails.
     *
     * @param  string  $key
     * @return mixed
     */
    public function get(string $key): mixed
    {
        return $this->attempt(fn (): mixed => $this->store->get($key));
    }

    /**
     * Store the entry at the key for the given number of seconds, unless the
     * store fails. A lifetime of zero or less forgets the key instead, as an
     * entry that has already lapsed is never stored.
     *
     * @param  string  $key
     * @param  array<string, mixed>  $entry
     * @param  int  $seconds
     * @return void
     */
    public function put(string $key, array $entry, int $seconds): void
    {
        $this->attempt(fn (): bool => $this->store->put($key, $entry, $seconds));
    }

    /**
     * Return the current token of each key, null for a key that has none, or
     * null in place of the whole map when the store fails.
     *
     * @param  list<string>  $keys
     * @return array<string, mixed>|null
     */
    public function tokens(array $keys): ?array
    {
        /** @var array<string, mixed>|null */
        return $this->attempt(fn (): array => \iterator_to_array($this->store->getMultiple($keys)));
    }

    /**
     * Return the current token of each key, first giving a token to any key
     * that has none, or null when the store fails or a token cannot be read
     * back.
     *
     * @param  list<string>  $keys
     * @return array<string, string>|null
     */
    public function pin(array $keys): ?array
    {
        $tokens  = $this->tokens($keys) ?? [];
        $missing = \array_keys(\array_filter($tokens, static fn (mixed $token): bool => !\is_string($token)));

        if ($missing !== []) {
            $this->attempt(function () use ($missing): void {
                foreach ($missing as $key) {
                    $this->store->add($key, self::token());
                }
            });

            $tokens = [...$tokens, ...($this->tokens($missing) ?? [])];
        }

        $pinned = \array_filter($tokens, 'is_string');

        return \count($pinned) === \count($keys) ? $pinned : null;
    }

    /**
     * Replace the tokens of the keys with a new one, throwing when the store
     * fails.
     *
     * @param  list<string>  $keys
     * @return void
     */
    public function bump(array $keys): void
    {
        $this->store->setMultiple(\array_fill_keys($keys, self::token()));
    }

    /**
     * Replace the tokens of the keys with a new one, writing a failure to the
     * log channel rather than throwing it.
     *
     * @param  list<string>  $keys
     * @return void
     */
    public function bumpQuietly(array $keys): void
    {
        try {
            $this->bump($keys);
        } catch (\Throwable $exception) { // @phpstan-ignore catch.neverThrown
            $this->fail($exception);
        }
    }

    /**
     * Run an operation on the store, unless it has already failed, and return
     * its result, or null when it fails.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $operation
     * @return TResult|null
     */
    private function attempt(\Closure $operation): mixed
    {
        if ($this->failed) {
            return null;
        }

        try {
            return $operation();
        } catch (\Throwable $exception) {
            $this->fail($exception);

            return null;
        }
    }

    /**
     * Stop using the store for the rest of the request or job, and say why.
     *
     * @param  \Throwable  $exception
     * @return void
     */
    private function fail(\Throwable $exception): void
    {
        $this->failed = true;

        AuthorizationLog::warning(
            'Authorization: the resolution cache store failed, so checks read the database for the rest of this request or job — ' . $exception->getMessage(),
            ['exception' => $exception],
        );
    }

    /**
     * Return a new random version token.
     *
     * @return string
     */
    private static function token(): string
    {
        return Str::random(16);
    }
}
