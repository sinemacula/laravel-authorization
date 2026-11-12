<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Marker interface implemented by every event the package dispatches: the
 * decision events, the role, permission and policy record events, the grant
 * events and the system override event.
 *
 * One listener, or one audit mapper registration, typed against this interface
 * covers them all. Every event other than the decision events is a final
 * readonly snapshot of plain values, carries the operation that made the change
 * (its id, actor and time), and is dispatched only once the write commits. Each
 * of them but `SystemOverrideUsed` reports a change to stored records and also
 * implements `AuthorizationMutation`, whose accessors an audit mapper reads
 * instead of the event's properties.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthorizationEvent {}
