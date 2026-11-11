<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * An action a subject may take in a scope, as `heldPermissionsFor()` lists it
 * (N128, N129), with every authentication requirement its decision read.
 *
 * The requirements are named as a policy document and the requirement checker
 * name their parts (`multifactor`, `phishing_resistant` and so on), each once,
 * sorted: every part of every requirement the decision read, on a statement or
 * a grant that allowed or on one that denied, or in a further check the
 * decision made, whether it was met or not, and whether or not it decided the
 * answer. An entry naming none is unconditional: no requirement was read, so
 * none could change the answer, and it is held whatever the session has proved.
 * The converse does not hold: one naming any is conditional, and may depend on
 * the session's authentication state as it is now, a fresh step-up say, though
 * a requirement read on a statement that did not decide the answer, such as an
 * allow beside another that needs nothing, is named all the same. Treat a
 * conditional entry as possibly held only while that state lasts.
 *
 * It holds the action and the part names alone: never the statement, the
 * policy, the session or any proof.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @api
 */
final readonly class HeldPermission
{
    /** @var list<string> The name of each part of every authentication requirement the decision read, once each, sorted; none when it read none. */
    public array $requirements;

    /**
     * Create a new held permission, keeping each requirement once, sorted.
     *
     * @param  string  $action
     * @param  array<int, string>  $requirements
     */
    public function __construct(

        /** The action the subject may take. */
        public string $action,

        // The name of each part of every authentication requirement the
        // decision read, in any order, any of them repeated.
        array $requirements = [],
    ) {
        $names = \array_unique($requirements);

        \sort($names, \SORT_STRING);

        $this->requirements = $names;
    }

    /**
     * Determine whether the action is held unconditionally: the decision read
     * no authentication requirement, so none could change its answer.
     *
     * @return bool
     */
    public function isUnconditional(): bool
    {
        return $this->requirements === [];
    }
}
