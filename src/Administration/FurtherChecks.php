<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * What the administration stage of one decision may ask of the decision
 * pipeline (see `OperationConstraints`): the acting subject, the tenant the
 * check is made from, before the operation's own tenant is put in place (see
 * `ResourceScope`), so the owner rule can compare it, and further checks of the
 * same subject, each decided as the pipeline decides any check, through every
 * stage up to the allow, in the scope in place when it is asked, but never
 * through the administration stage itself, so a constraint that decides the
 * operation's own action again in another scope cannot recurse.
 *
 * What could limit a right across a reach is read once per decision for each
 * right, reach and scope in place (see `limited()`), so a change that weighs
 * the same right for every role, permission or policy it hands out reads its
 * limits once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FurtherChecks
{
    /** @var \ArrayObject<string, bool> Whether each right was found limited, keyed by the right, the reach and the scope in place. */
    private \ArrayObject $limits;

    /**
     * Create the further checks of one decision.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \Closure(string, \SineMacula\Laravel\Authorization\Support\ResourceReference|null): \SineMacula\Laravel\Authorization\Evaluation\Decision  $decide
     * @param  \Closure(string): (\SineMacula\Laravel\Authorization\Evaluation\CheckSources|null)  $sources
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $from
     */
    public function __construct(

        /** The acting subject the decision is about. */
        public Subject $subject,

        /** Decides a further check of the subject in the scope in place. */
        private \Closure $decide,

        /** Gathers the sources of a further check of the subject, on no resource, in the scope in place, or null when a document cannot be read. */
        private \Closure $sources,

        /** The tenant the check is made from; null for the platform. */
        public ?Reference $from = null,
    ) {
        $this->limits = self::noLimits();
    }

    /**
     * Decide the action for the subject on the resource, or on none, in the
     * scope in place, through every stage up to the allow.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public function decide(string $action, ?ResourceReference $resource = null): Decision
    {
        return ($this->decide)($action, $resource);
    }

    /**
     * Gather the sources a check of the action for the subject, on no resource,
     * is decided from, in the scope in place, or null when a policy, boundary
     * or guardrail document among them cannot be read.
     *
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckSources|null
     */
    public function sources(string $action): ?CheckSources
    {
        return ($this->sources)($action);
    }

    /**
     * Return whether the right named by the key is limited across its reach,
     * working it out through the callback the first time the key is asked and
     * remembering it for the rest of this decision.
     *
     * @param  string  $key
     * @param  \Closure(): bool  $limit
     * @return bool
     */
    public function limited(string $key, \Closure $limit): bool
    {
        $known = $this->limits->offsetExists($key) ? $this->limits->offsetGet($key) : null;

        if ($known !== null) {
            return $known;
        }

        $isLimited = $limit();

        $this->limits->offsetSet($key, $isLimited);

        return $isLimited;
    }

    /**
     * Return an empty record of what was found limited.
     *
     * @return \ArrayObject<string, bool>
     */
    private static function noLimits(): \ArrayObject
    {
        return new \ArrayObject;
    }
}
