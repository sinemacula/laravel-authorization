<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Support\Facades\Event;

/**
 * Reads the events a faked dispatcher recorded, typed as their class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ReadsDispatchedEvents
{
    /**
     * Return every recorded event of the class, in the order dispatched.
     *
     * @template TEvent of object
     *
     * @param  class-string<TEvent>  $class
     * @return list<TEvent>
     */
    protected static function dispatchedEvents(string $class): array
    {
        $events = [];

        foreach (Event::dispatched($class)->all() as $call) {
            $event = \is_array($call) ? $call[0] ?? null : null;

            if (!$event instanceof $class) {
                continue;
            }

            $events[] = $event;
        }

        return $events;
    }
}
