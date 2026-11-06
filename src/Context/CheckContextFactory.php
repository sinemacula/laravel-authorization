<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\ContextSource;
use SineMacula\Laravel\Authorization\Contracts\EnvironmentContext;
use SineMacula\Laravel\Authorization\Contracts\RequestContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;

/**
 * Makes the context of each check from its sources (N26, N27).
 *
 * The trusted sources supply `authentication` (and any namespace the
 * authentication context contributes), `request` and `environment`; the
 * application's sources supply their own namespaces; and what the caller passes
 * is held under `input`, never promoted into another namespace, so a caller
 * passing `['request' => ['ip' => …]]` supplies `input.request.ip`, never
 * `request.ip`. Each check's context is new, and builds a namespace only when a
 * statement of the check reads it, at most once.
 *
 * A source claiming a namespace that is not a name (letters, digits and `_`),
 * is reserved, or is supplied by another source or the authentication context,
 * is refused on construction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CheckContextFactory
{
    /** @var string The namespace that holds what the caller passes. */
    public const string INPUT = 'input';

    /** @var string What a namespace may be: letters, digits and `_`, starting with a letter or `_`. */
    public const string NAMESPACE_PATTERN = '/\A[A-Za-z_][A-Za-z0-9_]*\z/';

    /** @var array<string, \Closure(): array<array-key, mixed>> The builder of each namespace a source supplies. */
    private array $builders;

    /**
     * Create a new check context factory.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthenticationContext  $authentication
     * @param  \SineMacula\Laravel\Authorization\Contracts\RequestContext  $request
     * @param  \SineMacula\Laravel\Authorization\Contracts\EnvironmentContext  $environment
     * @param  iterable<\SineMacula\Laravel\Authorization\Contracts\ContextSource>  $sources
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(AuthenticationContext $authentication, RequestContext $request, EnvironmentContext $environment, iterable $sources = [])
    {
        $builders = self::authenticationBuilders($authentication);

        foreach ($sources as $source) {
            $namespace = $source->namespace();

            self::assertClaimable($namespace, $builders, $source::class);

            $builders[$namespace] = static fn (): array => self::namespaced($namespace, $source->values());
        }

        $builders['request']     = static fn (): array => self::namespaced('request', $request->values());
        $builders['environment'] = static fn (): array => self::namespaced('environment', $environment->values());

        $this->builders = $builders;
    }

    /**
     * Make the context of one check, holding what the caller passes under
     * `input`.
     *
     * @param  array<array-key, mixed>  $input
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckContext
     */
    public function make(array $input = []): CheckContext
    {
        return new CheckContext([self::INPUT => $input], $this->builders);
    }

    /**
     * Return the one builder of every namespace the authentication context
     * supplies, refusing a reserved namespace other than `authentication`.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthenticationContext  $authentication
     * @return array<string, \Closure(): array<array-key, mixed>>
     *
     * @throws \InvalidArgumentException
     */
    private static function authenticationBuilders(AuthenticationContext $authentication): array
    {
        $builder  = static fn (): array => $authentication->values();
        $builders = ['authentication' => $builder];

        foreach (\array_diff($authentication->namespaces(), ['authentication']) as $namespace) {
            self::assertClaimable($namespace, $builders, $authentication::class);

            $builders[$namespace] = $builder;
        }

        return $builders;
    }

    /**
     * Refuse a namespace that is not a name, is reserved or is supplied by
     * another source.
     *
     * @param  string  $namespace
     * @param  array<string, \Closure(): array<array-key, mixed>>  $builders
     * @param  string  $source
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertClaimable(string $namespace, array $builders, string $source): void
    {
        $isClaimable = \preg_match(self::NAMESPACE_PATTERN, $namespace) === 1
            && !\in_array($namespace, ContextSource::RESERVED_NAMESPACES, true)
            && !isset($builders[$namespace]);

        if (!$isClaimable) {
            $reason = 'it is not a name, is reserved or is supplied by another source';

            throw new \InvalidArgumentException("Context source {$source} cannot supply the namespace '{$namespace}': {$reason}.");
        }
    }

    /**
     * Key a source's values by its namespace, leaving the namespace absent when
     * it supplies none.
     *
     * @param  string  $namespace
     * @param  array<array-key, mixed>  $values
     * @return array<string, array<array-key, mixed>>
     */
    private static function namespaced(string $namespace, array $values): array
    {
        return $values === [] ? [] : [$namespace => $values];
    }
}
