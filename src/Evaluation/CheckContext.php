<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * The context of one check: nested namespaces (`authentication`, `request`,
 * `environment`, `input` and any an application source adds), each read as a
 * dot path, segment by segment (N24).
 *
 * A namespace is given already built (the caller's `input`) or built by a
 * builder the first time a statement of the check reads it, and at most once
 * for the check: the namespaces no statement reads are never built. A builder
 * returns its namespaces' values keyed by namespace, and may build several
 * namespaces at once (the authentication context builds `authentication` and
 * any `mfa` or `sso` namespace it contributes); a namespace it leaves out is
 * absent, so its keys are missing. Build a new context for every check, so no
 * value outlives the check that read it.
 *
 * A path is never a literal flat key: `request.ip` reads the `ip` key of the
 * `request` namespace, and a top-level key named `request.ip` is never read.
 * The one resolver keeps a missing key (an absent namespace or key, a segment
 * read through a value that is not an array, an empty segment) apart from a key
 * present with a null value, which conditions and `${…}` interpolation alike
 * rely on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CheckContext
{
    /** @var array<array-key, mixed> The namespaces built so far, keyed by name. */
    private array $namespaces;

    /** @var array<string, \Closure(): array<array-key, mixed>> The builders not yet run, by each namespace they build. */
    private array $builders;

    /**
     * Create a new check context.
     *
     * A namespace given already built is never built again, so a builder for it
     * is ignored.
     *
     * @param  array<array-key, mixed>  $namespaces
     * @param  array<string, \Closure(): array<array-key, mixed>>  $builders
     */
    public function __construct(array $namespaces = [], array $builders = [])
    {
        $this->namespaces = $namespaces;
        $this->builders   = \array_diff_key($builders, $namespaces);
    }

    /**
     * Return the context itself, or a context whose namespaces are the given
     * array, already built.
     *
     * @param  array<array-key, mixed>|self  $context
     * @return self
     */
    public static function from(array|self $context): self
    {
        return $context instanceof self ? $context : new self($context);
    }

    /**
     * Read a dot path, such as `request.ip`.
     *
     * Returns whether the key is present and its value, which is null both for
     * a missing key and for a key present with a null value.
     *
     * @param  string  $path
     * @return array{bool, mixed}
     */
    public function lookup(string $path): array
    {
        return $this->find(\explode('.', $path));
    }

    /**
     * Read a path given as its segments, the namespace first, building the
     * namespace if no statement of the check has read it yet.
     *
     * Returns whether the key is present and its value, which is null both for
     * a missing key and for a key present with a null value.
     *
     * @param  list<string>  $segments
     * @return array{bool, mixed}
     */
    public function find(array $segments): array
    {
        [$isPresent, $value] = $this->namespaceOf($segments[0] ?? '');

        for ($index = 1, $count = \count($segments); $isPresent && $index < $count; $index++) {
            $segment   = $segments[$index];
            $isPresent = \is_array($value) && $segment !== '' && \array_key_exists($segment, $value);
            $value     = $isPresent ? $value[$segment] : null;
        }

        return [$isPresent, $value];
    }

    /**
     * Return whether the namespace is present and its values, building it on
     * the first read.
     *
     * @param  string  $namespace
     * @return array{bool, mixed}
     */
    private function namespaceOf(string $namespace): array
    {
        if (isset($this->builders[$namespace])) {
            $this->build($this->builders[$namespace]);
        }

        $isPresent = $namespace !== '' && \array_key_exists($namespace, $this->namespaces);

        return [$isPresent, $isPresent ? $this->namespaces[$namespace] : null];
    }

    /**
     * Run a builder once and keep every namespace it builds, leaving absent
     * those it was to build but left out.
     *
     * @param  \Closure(): array<array-key, mixed>  $builder
     * @return void
     */
    private function build(\Closure $builder): void
    {
        $built = $builder();

        foreach (\array_keys($this->builders, $builder, true) as $namespace) {
            unset($this->builders[$namespace]);

            if (!\array_key_exists($namespace, $built)) {
                continue;
            }

            $this->namespaces[$namespace] = $built[$namespace];
        }
    }
}
