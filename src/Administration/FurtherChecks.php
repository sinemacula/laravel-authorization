<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * What the administration stage of one decision may ask of the decision
 * pipeline (see `OperationConstraints`): the acting subject, and further checks
 * of the same subject, each decided as the pipeline decides any check, through
 * every stage up to the allow, in the scope in place when it is asked, but
 * never through the administration stage itself, so a constraint that decides
 * the operation's own action again in another scope cannot recurse.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class FurtherChecks
{
    /**
     * Create the further checks of one decision.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \Closure(string, \SineMacula\Laravel\Authorization\Support\ResourceReference|null): \SineMacula\Laravel\Authorization\Evaluation\Decision  $decide
     * @param  \Closure(string): (\SineMacula\Laravel\Authorization\Evaluation\CheckSources|null)  $sources
     */
    public function __construct(

        /** The acting subject the decision is about. */
        public Subject $subject,

        /** Decides a further check of the subject in the scope in place. */
        private \Closure $decide,

        /** Gathers the sources of a further check of the subject, on no resource, in the scope in place, or null when a document cannot be read. */
        private \Closure $sources,
    ) {}

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
}
