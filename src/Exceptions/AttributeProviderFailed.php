<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when an attribute provider fails to supply the attributes a check
 * reads (N31): it could not be resolved, or it threw.
 *
 * The check is aborted rather than decided with the attributes missing, so a
 * failing provider never allows anything. The message names the provider's
 * class and the namespace it supplies, never an attribute value, and nothing of
 * the original failure, which is kept as the previous exception, reaches a
 * decision, an event or the trace (AUTHZ-8.8).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class AttributeProviderFailed extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $provider
     * @param  string  $namespace
     * @param  \Throwable  $previous
     */
    public function __construct(

        /** Class of the provider that failed. */
        private readonly string $provider,

        /** Namespace the provider supplies: `resource` or `subject`. */
        private readonly string $namespace,

        // The failure the provider raised.
        \Throwable $previous,
    ) {
        parent::__construct("Attribute provider '{$provider}' failed to supply the '{$namespace}' namespace, so the check was aborted.", 0, $previous);
    }

    /**
     * Return the class of the provider that failed.
     *
     * @return string
     */
    public function getProvider(): string
    {
        return $this->provider;
    }

    /**
     * Return the namespace the provider supplies.
     *
     * @return string
     */
    public function getNamespace(): string
    {
        return $this->namespace;
    }
}
