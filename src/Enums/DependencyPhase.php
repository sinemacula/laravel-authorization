<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

/**
 * Which part of a delegated operation's dependencies a lock is taken for, in
 * the one order every delegated operation takes its locks (see
 * `Administration\DependencyPins`): the actor's authority first, then the
 * records the operation changes, then the holders and the resource policies a
 * change reaches, then, last, the grants a grant hook's coverage check reads
 * again once every decision is made. A later part never locks before an earlier
 * one within an operation. The order does not stop two operations deadlocking
 * when they cross, one's actor being the other's target, so each holds a row
 * the other waits for: the database detects that deadlock and refuses one of
 * them, which is tried again when it opened the transaction.
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

    /** The rows that name the holders a change to a shared definition reaches, and the resource policies and guardrails a decision reads across a grant's reach. */
    case HOLDERS = 2;

    /** The grants of the identity and its principals that applied in a tenant a grant is written in, the evidence a grant hook was skipped or limited on, read again under the lock before the write (see `Hooks\WideningPhase`). */
    case COVERAGE = 3;
}
