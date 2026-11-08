<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown inside a delegated operation when something its decisions read changed
 * before it wrote (see `Administration\DependencyPins`): a row the decision
 * depends on was written, added or removed, or the tenant tree moved. Thrown
 * too, inside a trusted or delegated grant, when a grant it is about to write
 * now widens an identity's scope although its grant hooks were not run for it
 * (see `Hooks\WideningPhase`).
 *
 * The operation is rolled back and tried again, up to
 * `authorization.administration.retries` times (a trusted operation only for a
 * widening, see `isWidening()`); once every try has failed, the caller gets an
 * `AuthorizationException` as `administration.conflict` instead (see
 * `Administration\ConflictRetries`), so this exception never leaves a
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
     * Create the exception with its message.
     *
     * @param  string  $message
     * @param  bool  $widens
     */
    private function __construct(

        // Not promoted: the message is the parent's to keep.
        string $message,

        /** Whether a grant now widens an identity's scope with no hook run for it. */
        private readonly bool $widens = false,
    ) {
        parent::__construct($message);
    }

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

    /**
     * Return the exception of a grant that widens an identity's scope with no
     * grant hook run for it: what the hook phase read changed before the write.
     *
     * @return self
     */
    public static function widening(): self
    {
        return new self('A grant now widens an identity\'s scope although its grant hooks were not run for it.', true);
    }

    /**
     * Determine whether the conflict is a grant that now widens an identity's
     * scope with no grant hook run for it, the one conflict a trusted operation
     * is tried again for.
     *
     * @return bool
     */
    public function isWidening(): bool
    {
        return $this->widens;
    }
}
