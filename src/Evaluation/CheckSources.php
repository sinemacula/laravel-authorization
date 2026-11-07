<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * Every source one check is decided from, gathered by the decision pipeline in
 * the scope the check is decided in: the policies, the guardrails, the
 * boundaries, the check's context, the permission held and the session caps.
 *
 * `whereAuthorized()` reads them as the pipeline gathered them, to tell whether
 * the statements they hold can be compiled, before the pipeline weighs them, so
 * a query is decided from exactly the sources `check()` is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CheckSources
{
    /**
     * Create the sources of a check.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>|null  $guardrails
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $boundaries
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @param  \Closure(): ?string  $permission
     * @param  \SineMacula\Laravel\Authorization\Evaluation\SessionCaps  $session
     */
    public function __construct(

        /** The policies the check reads: the subject's, its identity's and the resource's, or an override. */
        public array $policies,

        /** The guardrails that cap the check; null when the check is exempt from them. */
        public ?array $guardrails,

        /** The permission boundaries of the subject and its identity. */
        public array $boundaries,

        /** The check's context. */
        public CheckContext $context,

        /** Answers the permission the subject holds that names the action, or null. */
        public \Closure $permission,

        /** The session caps the check is decided under. */
        public SessionCaps $session,
    ) {}
}
