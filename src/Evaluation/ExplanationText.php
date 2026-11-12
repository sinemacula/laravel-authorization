<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Renders an explanation as text, for reading (AUTHZ-11.5): the verdict and
 * what decided it, each requirement, each step of every stage reached with its
 * condition tests, the stages not evaluated, the grants' provenance, the keys
 * found missing and the request, and, for a decision made without explain mode,
 * that the rest was not recorded.
 *
 * Every name is escaped as a JSON string is: `<`, `>`, `&` and non-ASCII
 * characters as `\uXXXX`, a quote and a backslash with a backslash, and a
 * control character as its JSON escape, `\b`, `\f`, `\n`, `\r` and `\t` in
 * short and any other as `\uXXXX` (`\u0001` say), so no policy, statement, key,
 * role or tenant name can inject markup, control characters or a line of its
 * own. Rendering reads the explanation alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExplanationText
{
    /** @var int The flags every name is encoded with. */
    private const int FLAGS = \JSON_UNESCAPED_SLASHES | \JSON_HEX_TAG | \JSON_HEX_AMP | \JSON_INVALID_UTF8_SUBSTITUTE | \JSON_THROW_ON_ERROR;

    /**
     * Render the explanation as text.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Explanation  $explanation
     * @return string
     */
    public static function render(Explanation $explanation): string
    {
        $lines = [self::verdict($explanation)];

        foreach ($explanation->requirements as $unmet) {
            $lines[] = '  requirement ' . self::names($unmet->requirement->names()) . ': unmet ' . self::names($unmet->unmet);
        }

        foreach ($explanation->steps as $step) {
            $lines = [...$lines, ...self::step($step)];
        }

        if ($explanation->notEvaluated !== []) {
            $lines[] = '  not evaluated: ' . \implode(', ', \array_map(static fn (DecisionStage $stage): string => $stage->value, $explanation->notEvaluated));
        }

        return \implode("\n", [...$lines, ...self::evidence($explanation)]);
    }

    /**
     * Return the name escaped, without quotes.
     *
     * @param  string  $name
     * @return string
     */
    public static function bare(string $name): string
    {
        return \substr(self::quoted($name), 1, -1);
    }

    /**
     * Return the name escaped and quoted.
     *
     * @param  string  $name
     * @return string
     */
    public static function quoted(string $name): string
    {
        return \json_encode($name, self::FLAGS);
    }

    /**
     * Return the statement reference as text: the policy's name, its stored
     * key, the statement's position, its sid and the resource its policy is
     * attached to, each escaped: `name[key]#index sid="sid" on "post:1"`.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $reference
     * @return string
     */
    public static function statement(StatementReference $reference): string
    {
        $key      = $reference->policyId === null ? '' : '[' . self::bare($reference->policyId) . ']';
        $sid      = $reference->sid      === null ? '' : ' sid=' . self::quoted($reference->sid);
        $resource = $reference->resource === null ? '' : ' on ' . self::quoted($reference->resource);

        return self::bare($reference->policy) . $key . "#{$reference->index}" . $sid . $resource;
    }

    /**
     * Return the first line: the verdict, the stage, and the statements, or the
     * cap or permission, that decided it.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Explanation  $explanation
     * @return string
     */
    private static function verdict(Explanation $explanation): string
    {
        $verdict = $explanation->isAllowed() ? 'ALLOW' : "DENY ({$explanation->reason?->value}: {$explanation->reason?->label()})";
        $by      = \implode(', ', \array_map(self::statement(...), $explanation->statements));
        $cause   = $explanation->cause;

        if ($by === '' && $cause !== null && $cause['names'] !== []) {
            $by = $cause['kind'] . ' ' . \implode(', ', \array_map(self::quoted(...), $cause['names']));
        }

        return "{$verdict} at the {$explanation->stage->value} stage" . ($by === '' ? '.' : " by {$by}.");
    }

    /**
     * Return the lines of one step: what it is about and found, with the keys
     * it tested, then each condition test it recorded, then the resource
     * pattern references it could not resolve.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\TraceEntry  $step
     * @return list<string>
     */
    private static function step(TraceEntry $step): array
    {
        $held = \array_map(
            static fn (string $key, bool $holds): string => self::bare($key) . ($holds ? ' held' : ' failed'),
            \array_map(\strval(...), \array_keys($step->conditions)),
            \array_values($step->conditions),
        );

        $lines = [
            "  [{$step->stage->value}] " . self::about($step) . ": {$step->outcome->value}" . ($held === [] ? '' : ' (' . \implode(', ', $held) . ')'),
            ...\array_map(self::test(...), $step->tests ?? []),
        ];

        if ($step->unresolved !== []) {
            $lines[] = '      resource pattern unresolved ' . self::references($step->unresolved);
        }

        return $lines;
    }

    /**
     * Return the line of one condition test: its key, its operator, what it
     * found, whether its key was missing, and the references of its operand
     * that could not be resolved.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ConditionResult  $test
     * @return string
     */
    private static function test(ConditionResult $test): string
    {
        return '      test ' . self::bare($test->key) . ' ' . self::bare($test->operator) . ($test->isOptional ? '_if_exists' : '') . ": {$test->outcome->value}"
            . ($test->isMissing ? ' (key missing)' : '')
            . ($test->unresolved === [] ? '' : ', unresolved ' . self::references($test->unresolved));
    }

    /**
     * Return what a step is about: the statement it assessed, else the cap it
     * is about, else the permission held, else what its stage weighs.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\TraceEntry  $step
     * @return string
     */
    private static function about(TraceEntry $step): string
    {
        $held = $step->permission === null ? null : 'permission ' . self::quoted($step->permission);
        $cap  = $step->cap        === null ? null : self::bare($step->cap);

        return ($step->statement === null ? null : self::statement($step->statement)) ?? $cap ?? $held ?? self::weighed($step->stage);
    }

    /**
     * Return what a stage weighs, as a step about no statement, cap or
     * permission held names it.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @return string
     */
    private static function weighed(DecisionStage $stage): string
    {
        return match ($stage) {
            DecisionStage::GUARDRAIL      => 'guardrails',
            DecisionStage::BOUNDARY       => 'boundaries',
            DecisionStage::SESSION        => 'session caps',
            DecisionStage::ADMINISTRATION => 'administration constraints',
            default                       => 'permission',
        };
    }

    /**
     * Return the lines of the explained check's evidence, the grants'
     * provenance, the keys found missing and the request, or the line saying it
     * was not recorded.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Explanation  $explanation
     * @return list<string>
     */
    private static function evidence(Explanation $explanation): array
    {
        $evidence = $explanation->evidence;

        if ($evidence === null) {
            return ['  evidence: ' . Explanation::NOT_RECORDED];
        }

        $lines   = \array_map(self::grant(...), $evidence->grants);
        $missing = $explanation->missingKeys();

        if ($missing !== []) {
            $lines[] = '  missing ' . self::names($missing);
        }

        if ($evidence->request !== null) {
            $lines[] = self::request($evidence->request);
        }

        return $lines;
    }

    /**
     * Return the line of one grant's provenance.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\GrantProvenance  $grant
     * @return string
     */
    private static function grant(GrantProvenance $grant): string
    {
        $line = '  grant ' . \str_replace('_', ' ', $grant->source->value) . ' ' . self::quoted($grant->grant);

        if ($grant->source === GrantSource::UNAVAILABLE) {
            return $line . ': provenance unavailable';
        }

        $party   = $grant->isIdentity ? ' to identity ' : ' to principal ';
        $grantee = $grant->grantee === null ? '' : $party . self::reference($grant->grantee);
        $roles   = $grant->roles   === [] ? '' : ' through role ' . \implode(' < ', \array_map(self::quoted(...), $grant->roles));
        $scope   = $grant->hasScope ? ' in ' . self::scope($grant->tenant, $grant->application) : ', scope unavailable';
        $glass   = $grant->activation === null ? '' : ' by break-glass activation ' . self::quoted($grant->activation);

        return $line . $grantee . $roles . $glass . $scope;
    }

    /**
     * Return the line of the request: the action, the resource, who it was
     * about and who previewed it, and the scope asked in and decided in.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ExplanationRequest  $request
     * @return string
     */
    private static function request(ExplanationRequest $request): string
    {
        $decided   = $request->decided;
        $resource  = $request->resource  === null ? '' : ' on ' . self::quoted($request->resource);
        $subject   = $decided->subject   === null ? ' about no saved subject' : ' about ' . self::reference($decided->subject);
        $identity  = $decided->identity  === null ? '' : ' (identity ' . self::reference($decided->identity) . ')';
        $previewer = $decided->previewer === null ? '' : ', previewed by ' . self::reference($decided->previewer);

        return '  request ' . self::quoted($request->action) . $resource . $subject . $identity . $previewer
            . '; asked in ' . self::scope($request->requested->tenant, $request->requested->application)
            . ', decided in ' . self::scope($decided->tenant, $decided->application);
    }

    /**
     * Return a scope as text: its tenant, or the platform, and its application
     * when it has one; none means every application.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @return string
     */
    private static function scope(?Reference $tenant, ?string $application): string
    {
        return ($tenant === null ? 'platform' : 'tenant ' . self::reference($tenant)) . ($application === null ? '' : ' for application ' . self::quoted($application));
    }

    /**
     * Return a reference as text, `type:id`, escaped.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $reference
     * @return string
     */
    private static function reference(Reference $reference): string
    {
        return self::bare($reference->type . ':' . $reference->id);
    }

    /**
     * Return the names, each escaped, separated by commas.
     *
     * @param  list<string>  $names
     * @return string
     */
    private static function names(array $names): string
    {
        return \implode(', ', \array_map(self::bare(...), $names));
    }

    /**
     * Return the references, each written `${key}` and escaped, separated by
     * commas.
     *
     * @param  list<string>  $references
     * @return string
     */
    private static function references(array $references): string
    {
        return \implode(', ', \array_map(static fn (string $reference): string => '${' . self::bare($reference) . '}', $references));
    }
}
