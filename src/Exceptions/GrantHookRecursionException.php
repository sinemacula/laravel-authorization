<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a package mutation service is called while a grant hook runs
 * (AUTHZ-11.3, N80).
 *
 * A hook may only veto: it never changes the grant, and it may not change any
 * other record of the package's either, since a call without an acting context
 * would be trusted and could hand out authority before the outer call is
 * decided. Every management service refuses while a hook runs; the read-only
 * queries, `GrantScopeQuery` among them, stay allowed. Calling one is a mistake
 * in the hook, not a refusal of the grant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GrantHookRecursionException extends \LogicException
{
    /**
     * Create a new exception instance.
     */
    public function __construct()
    {
        parent::__construct('A grant hook may not call a management service of the authorization package; a hook may only refuse the grant by throwing.');
    }
}
