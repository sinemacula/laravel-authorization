<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a grant that widens an identity's scope is made inside another
 * management call's work, such as from a model observer or a listener that
 * call's own writes fire (AUTHZ-11.3).
 *
 * The outer call may already hold the package's locks, so the grant's hook
 * cannot run before every lock the package takes, and is never skipped instead.
 * Make the grant as a call of its own: in a transaction of the application's,
 * before any call that takes the package's locks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class NestedGrantException extends \LogicException
{
    /**
     * Create a new exception instance.
     */
    public function __construct()
    {
        parent::__construct('A grant that widens an identity\'s scope cannot be made inside another management call, after it may have taken locks; '
            . 'make it as a call of its own, before any call that takes the package\'s locks.');
    }
}
