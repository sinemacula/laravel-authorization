<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Carbon\CarbonImmutable;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authorization\Administration\ActingContext;

/**
 * One call that changes the package's records, as every event it dispatches
 * reports it: an id shared by those events, for correlation, who made the call
 * and how, the administration actions its changes fall under, and when it was
 * made. The actions are decided through `check()` only for a delegated call: a
 * trusted call names them too, though nothing was decided, a sync names both
 * its grant and its revoke action, whichever it made, and a write made through
 * a model outside the services names none.
 *
 * A call made with an acting context is delegated: its actor is the acting
 * subject's principal, with the identity behind it and, while impersonating,
 * the impersonator, and each change it made was decided through `check()` on an
 * operation resource whose id is this operation's, so a decision and the events
 * of the write it allowed share the id. A call made without one is trusted
 * system work (N75): it has no actor, unless a console command names one by
 * reference for the record alone, and nothing was decided for it.
 *
 * Each management service call is one operation, as is a write made through a
 * model outside the services, which is trusted and names no actor.
 *
 * The client, the IP address and the user agent the call came from, is that of
 * the routed request a delegated operation is begun in (see `RequestClient`),
 * or what the caller passes, and is null for trusted, console and queued work
 * unless the caller passes it. Both are personal data, carried to the grant
 * hook alone (see `Hooks\GrantWidening`): the work of the call, and every event
 * it dispatches, see the operation without them (`withoutClient()`), and they
 * are never put in a cache key, a decision event, a log or a stored row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Operation
{
    /**
     * Create a new operation.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \DateTimeImmutable  $at
     * @param  bool  $isTrusted
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $identity
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $impersonator
     * @param  list<string>  $actions
     * @param  string|null  $ip
     * @param  string|null  $userAgent
     */
    public function __construct(

        /** The operation's id, a UUID shared by every event it dispatches and every decision made for it. */
        public string $id,

        /** Who made the call: the acting subject's principal, the reference a trusted command names, or null for system work. */
        public ?Reference $actor,

        /** When the call was made, in UTC. */
        public \DateTimeImmutable $at,

        /** Whether the call is trusted system work, made without an acting context, so nothing was decided for it. */
        public bool $isTrusted = true,

        /** The identity behind the acting principal, or null for none or a trusted call. */
        public ?Reference $identity = null,

        /** Who was impersonating the acting subject, or null when no one was. */
        public ?Reference $impersonator = null,

        /** The administration actions the call's changes fall under, each once, decided through `check()` only when the call is not trusted. */
        public array $actions = [],

        /** The IP address the call came from, or null when unknown: personal data, for the grant hook alone. */
        public ?string $ip = null,

        /** The user agent the call came from, or null when unknown: personal data, for the grant hook alone. */
        public ?string $userAgent = null,
    ) {}

    /**
     * Begin a new operation, with a new id, now: delegated for an acting
     * context, else trusted, attributed to the reference a trusted command
     * names, or to no one.
     *
     * The client is the one given, kept as it is when either value is given;
     * else a delegated operation takes the client of the routed request it is
     * begun in, and a trusted one, or one begun outside a routed request, such
     * as in a console command or a queued job, has none.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  list<string>  $actions
     * @param  string|null  $ip
     * @param  string|null  $userAgent
     * @return self
     */
    public static function begin(ActingContext|Reference|null $actor = null, array $actions = [], ?string $ip = null, ?string $userAgent = null): self
    {
        $id      = (string) Str::uuid();
        $at      = CarbonImmutable::now('UTC');
        $actions = \array_values(\array_unique($actions));

        if (!$actor instanceof ActingContext) {
            return new self($id, $actor, $at, true, null, null, $actions, $ip, $userAgent);
        }

        [$ip, $userAgent] = $ip === null && $userAgent === null ? RequestClient::current() : [$ip, $userAgent];

        return new self($id, $actor->principal(), $at, false, $actor->identity(), $actor->impersonator, $actions, $ip, $userAgent);
    }

    /**
     * Return this operation without its client, or itself when it has none:
     * what the call's work, and every event it dispatches, are given, so the
     * client reaches the grant hook alone.
     *
     * @return self
     */
    public function withoutClient(): self
    {
        if ($this->ip === null && $this->userAgent === null) {
            return $this;
        }

        return new self($this->id, $this->actor, $this->at, $this->isTrusted, $this->identity, $this->impersonator, $this->actions);
    }
}
