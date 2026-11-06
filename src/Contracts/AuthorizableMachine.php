<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Authorizable machine contract (AUTHZ-2.4).
 *
 * Marks a principal that is a machine: a service account, an integration, a
 * client acting for no person. Its grants work as a person's, intersected with
 * the scopes of its credential (AUTHZ-7.5), which it must have: with no scopes
 * from the session policy source, a machine is allowed nothing, and
 * `Authorization::capped()` only narrows its scopes further, never standing in
 * for them.
 *
 * A machine is never treated as a person: the grants and policies of a
 * subject's identity reach the subject only when both are machines or neither
 * is, so a person's grants never reach a machine and a machine's never reach a
 * person.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthorizableMachine {}
