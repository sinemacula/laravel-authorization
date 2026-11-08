<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown inside a delegated operation when something its decisions read changed
 * before it wrote (see `Administration\DependencyPins`): a row the decision
 * depends on was written, added or removed, or the tenant tree moved.
 *
 * The operation is rolled back and tried again, up to
 * `authorization.administration.retries` times; once every try has failed, the
 * caller gets an `AuthorizationException` as `administration.conflict` instead
 * (see `Administration\ConflictRetries`), so this exception never leaves a
 * management service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DependencyChangedException extends \RuntimeException
{
    /**
     * Return the exception of rows of the table that changed.
     *
     * @param  string  $table
     * @return self
     */
    public static function rows(string $table): self
    {
        return new self("The rows of [{$table}] a delegated decision read changed before the write.");
    }

    /**
     * Return the exception of a tenant tree that moved.
     *
     * @return self
     */
    public static function tree(): self
    {
        return new self('The tenant tree moved after a delegated decision read it, before the write.');
    }
}
