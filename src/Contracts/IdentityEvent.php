<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Marker interface for identity-mutation events.
 *
 * All events under `Events\Identity\` carry an `authorizable` property
 * describing the identity whose grants have changed. Implementing this
 * interface lets listeners accept the full set with a single type hint rather
 * than a long union.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface IdentityEvent {}
