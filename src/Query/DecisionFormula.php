<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Evaluation\StatementEntries;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;

/**
 * Compiles how one class of rows is decided from the sources gathered for it
 * into the condition a row of the class meets when `check()` allows it, stage
 * by stage as the policy evaluator decides a check (`PolicyEvaluator`):
 *
 * - no deny applies: every deny statement of every policy, guardrail and
 *   boundary that names the action, each applying where it matches the row or
 *   cannot be decided on it, and each deny of a policy attached to the row's
 *   record, applying to everyone, where the attachment holds;
 * - every guardrail, unless the check is exempt from them, and every boundary
 *   has an allow statement that names the action and matches the row;
 * - every session cap covers the action;
 * - an allow statement that names the action and applies to the subject matches
 *   the row, one of a policy attached to the row's record where the attachment
 *   holds, or the subject holds the action's permission.
 *
 * The statements are gathered in the evaluator's order (`StatementEntries`),
 * and each is compiled by the statement screen, which refuses one that cannot
 * be, so an invalid statement that bears on a row never reaches the condition.
 * A statement of a policy attached to records is weighed only on the rows whose
 * record it is attached to, at most 191 bytes long, so it is left out of
 * whether a pattern is matched against every row's identifier.
 *
 * @phpstan-import-type StatementEntry from \SineMacula\Laravel\Authorization\Evaluation\StatementEntries
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DecisionFormula
{
    /** @var bool Whether a statement weighed on every row has a resource pattern that resolves. */
    private bool $isPatterned = false;

    /**
     * Create a new decision formula.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Query\StatementScreen  $screen
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     */
    private function __construct(

        /** The action the query is scoped to. */
        private readonly string $action,

        /** Compiles each statement, keeping the refusals. */
        private readonly StatementScreen $screen,

        /** The class's context, its principal selectors fresh for the class. */
        private readonly CheckContext $context,
    ) {}

    /**
     * Return the condition a row of the class meets when `check()` allows it,
     * from the sources gathered for the class, whether the subject holds the
     * action's permission in its scope, and the policies attached to records,
     * each with the condition a row meets when it is attached to the row's
     * record and whether only its denies count; and whether a statement weighed
     * on every row has a resource pattern that resolves.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Query\StatementScreen  $screen
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckSources  $sources
     * @param  bool  $isHeld
     * @param  list<array{\SineMacula\Laravel\Authorization\Evaluation\Policy, string, bool}>  $attached
     * @return array{string, bool}
     */
    public static function of(string $action, StatementScreen $screen, CheckSources $sources, bool $isHeld, array $attached = []): array
    {
        $formula  = new self($action, $screen, $sources->context);
        $gathered = (new StatementEntries)->of($sources->policies, $sources->boundaries, $sources->guardrails);

        $decision = Conditions::all([
            Conditions::not($formula->denies($gathered['deny'], $attached)),
            $formula->caps($gathered['guardrails']),
            $formula->caps($gathered['boundaries']),
            self::session($sources->session, $action),
            Conditions::any([$formula->allows($gathered['allow'], $attached), $isHeld ? QueryAuthorizer::EVERY_ROW : QueryAuthorizer::NO_ROW]),
        ]);

        return [$decision, $formula->isPatterned];
    }

    /**
     * Return the condition a row meets when a deny applies to it.
     *
     * @param  list<StatementEntry>  $entries
     * @param  list<array{\SineMacula\Laravel\Authorization\Evaluation\Policy, string, bool}>  $attached
     * @return string
     */
    private function denies(array $entries, array $attached): string
    {
        $denies = [];

        foreach ($entries as [$reference, $statement]) {
            $denies[] = $statement->coversAction($this->action) ? $this->termsOf($reference, $statement, true)[1] : QueryAuthorizer::NO_ROW;
        }

        foreach ($this->attachedStatements($attached, PolicyEffect::DENY) as [$reference, $statement, $condition]) {
            $denies[] = Conditions::all([$condition, $this->termsOf($reference, $statement, false)[1]]);
        }

        return Conditions::any($denies);
    }

    /**
     * Return the condition a row meets when every cap of a stage allows it,
     * each by an allow statement that names the action and matches the row;
     * every row's when the caps are null, the check being exempt from them.
     *
     * @param  list<array{list<StatementEntry>, \SineMacula\Laravel\Authorization\Evaluation\TraceEntry}>|null  $caps
     * @return string
     */
    private function caps(?array $caps): string
    {
        $passed = [];

        foreach ($caps ?? [] as [$entries]) {
            $passed[] = $this->allows($entries, []);
        }

        return Conditions::all($passed);
    }

    /**
     * Return the condition a row meets when an allow statement that names the
     * action and applies to the subject matches it.
     *
     * @param  list<StatementEntry>  $entries
     * @param  list<array{\SineMacula\Laravel\Authorization\Evaluation\Policy, string, bool}>  $attached
     * @return string
     */
    private function allows(array $entries, array $attached): string
    {
        $allows = [];

        foreach ($entries as [$reference, $statement]) {
            $allows[] = $this->isWeighed($reference, $statement) ? $this->termsOf($reference, $statement, true)[0] : QueryAuthorizer::NO_ROW;
        }

        foreach ($this->attachedStatements($attached, PolicyEffect::ALLOW) as [$reference, $statement, $condition]) {
            $allows[] = $this->isWeighed($reference, $statement) ? Conditions::all([$condition, $this->termsOf($reference, $statement, false)[0]]) : QueryAuthorizer::NO_ROW;
        }

        return Conditions::any($allows);
    }

    /**
     * Return each statement of the effect of the policies attached to records,
     * with its reference and the condition a row meets when its policy is
     * attached to the row's record; an attachment whose denies alone count
     * gives no allow.
     *
     * @param  list<array{\SineMacula\Laravel\Authorization\Evaluation\Policy, string, bool}>  $attached
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect  $effect
     * @return list<array{\SineMacula\Laravel\Authorization\Evaluation\StatementReference, \SineMacula\Laravel\Authorization\Evaluation\Statement, string}>
     */
    private function attachedStatements(array $attached, PolicyEffect $effect): array
    {
        $statements = [];

        foreach ($attached as [$policy, $condition, $isDenyOnly]) {
            foreach ($effect === PolicyEffect::ALLOW && $isDenyOnly ? [] : $policy->statements as $index => $statement) {
                if ($statement->effect !== $effect || !$statement->coversAction($this->action)) {
                    continue;
                }

                $statements[] = [new StatementReference($policy->name, $index, $policy->id, $statement->sid, $policy->resource), $statement, $condition];
            }
        }

        return $statements;
    }

    /**
     * Determine whether an allow statement is weighed: it names the action and
     * applies to the subject, as its source admits.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $reference
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @return bool
     */
    private function isWeighed(StatementReference $reference, Statement $statement): bool
    {
        return $statement->coversAction($this->action) && PolicyEvaluator::isForSubject($reference, $statement, $this->context);
    }

    /**
     * Return the conditions a row meets when the statement matches it and when
     * it applies to it, noting a resolved pattern of a statement weighed on
     * every row.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $reference
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  bool  $isEveryRow
     * @return array{string, string}
     */
    private function termsOf(StatementReference $reference, Statement $statement, bool $isEveryRow): array
    {
        [$matches, $applies, $isPatterned] = $this->screen->terms($reference, $statement, $this->context);

        $this->isPatterned = $this->isPatterned || ($isEveryRow && $isPatterned);

        return [$matches, $applies];
    }

    /**
     * Return the condition every row meets when every session cap covers the
     * action, none when one does not.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\SessionCaps  $session
     * @param  string  $action
     * @return string
     */
    private static function session(SessionCaps $session, string $action): string
    {
        foreach ($session->caps as [, $patterns]) {
            if (!SessionCaps::covers($patterns, $action)) {
                return QueryAuthorizer::NO_ROW;
            }
        }

        return QueryAuthorizer::EVERY_ROW;
    }
}
