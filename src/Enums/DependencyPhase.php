<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

/**
 * Which part of a delegated operation's dependencies a lock is taken for, in
 * the one order every delegated operation takes its locks (see
 * `Administration\DependencyPins`): the actor's authority first, then the
 * records the operation changes, then the holders a change reaches. A later
 * part never locks before an earlier one, so two operations never wait on each
 * other's locks in opposite orders over the same parts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum DependencyPhase: int
{
    /** The actor's grants, roles and role chain, boundaries, the guardrails in its reach and the policies of the operation type. */
    case ACTOR = 0;

    /** The records the operation changes: the grant rows, roles, permissions and policies, and the tenants it holds in. */
    case TARGET = 1;

    /** The rows that name the holders a change to a shared definition reaches. */
    case HOLDERS = 2;
}
