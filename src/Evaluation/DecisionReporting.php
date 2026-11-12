<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Config\ConfigValue;
use SineMacula\Laravel\Authorization\Config\EventConfigValidator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;

/**
 * Which decisions `DecisionEvaluated` reports, as
 * `authorization.events.decisions` sets it (BL-72), and why each is reported.
 *
 * Each setting reports a kind of decision on its own: `previews` every decision
 * made through a preview, `insufficient_authentication` every denial whose only
 * unmet requirement is authentication, `denials` every denial, and `allows`
 * every allow (`all`), the allows of the `sensitive_actions` alone
 * (`sensitive`, the default) or none. A decision is reported when a setting
 * that is on reports it, for the first reason, in the order `DecisionReport`
 * declares them, that applies to it and is reported: a preview's denial is
 * reported as a preview while `previews` is on, and as a denial while it is off
 * and `denials` is on. A break-glass allow is to be reported whatever the
 * settings (BL-72b); no decision uses a break-glass grant yet.
 *
 * The settings are read once for each batch of checks that reports its
 * decisions (see `CheckBatch`), so each decision costs a few comparisons and
 * one lookup of its action. `AuthorizationFailed` is not filtered: every hard
 * refusal is reported, for the reason it would have with every setting on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DecisionReporting
{
    /** @var string Every allow is reported. */
    public const string ALL = 'all';

    /** @var string The allows of the sensitive actions alone are reported. */
    public const string SENSITIVE = 'sensitive';

    /** @var string No allow is reported. */
    public const string NONE = 'none';

    /** @var list<string> What `allows` may be set to. */
    public const array ALLOWS = [self::ALL, self::SENSITIVE, self::NONE];

    /** @var array<string, true> Each sensitive action, as a key. */
    private array $sensitive;

    /**
     * Create a new set of reporting settings.
     *
     * @param  bool  $denials
     * @param  bool  $insufficientAuthentication
     * @param  bool  $previews
     * @param  string  $allows
     * @param  list<string>  $sensitiveActions
     */
    public function __construct(

        /** Whether every denial is reported. */
        private bool $denials = true,

        /** Whether every denial whose only unmet requirement is authentication is reported. */
        private bool $insufficientAuthentication = true,

        /** Whether every decision made through a preview is reported. */
        private bool $previews = true,

        /** Which allows are reported: `all`, `sensitive` or `none`. */
        private string $allows = self::SENSITIVE,

        // The actions whose allows are reported while `allows` is not `none`.
        array $sensitiveActions = [],
    ) {
        $this->sensitive = \array_fill_keys($sensitiveActions, true);
    }

    /**
     * Return the reporting settings as the configuration holds them now,
     * refusing a value that is not one its setting takes.
     *
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function configured(): self
    {
        return EventConfigValidator::reporting(ConfigValue::block('events.decisions'));
    }

    /**
     * Return the reporting settings with every setting on and every allow
     * reported, which report every decision for the most specific reason it
     * has: how `AuthorizationFailed` names its reason.
     *
     * @return self
     */
    public static function everything(): self
    {
        return new self(allows: self::ALL);
    }

    /**
     * Return the event reporting the decision on the action and the resource,
     * made with the provenance given, or null when the settings do not report
     * it.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance  $provenance
     * @param  string  $action
     * @param  false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null  $reference
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Events\DecisionEvaluated|null
     */
    public function evaluated(DecisionProvenance $provenance, string $action, false|ResourceReference|null $reference, Decision $decision): ?DecisionEvaluated
    {
        $report = $this->reportOf($decision->effect, $decision->reason, $action, $provenance->previewer !== null);

        return $report === null ? null : DecisionEvaluated::of($provenance, $action, ResourceReferences::identifierOf($reference), $decision, $report, $this->isSensitive($action));
    }

    /**
     * Return the event reporting the refusal of the action on the resource,
     * made with the provenance given, whatever the settings, for the reason it
     * has with every setting on.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance  $provenance
     * @param  string  $action
     * @param  false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null  $reference
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Events\AuthorizationFailed
     */
    public function failed(DecisionProvenance $provenance, string $action, false|ResourceReference|null $reference, Decision $decision): AuthorizationFailed
    {
        return AuthorizationFailed::of($provenance, $action, ResourceReferences::identifierOf($reference), $decision, isSensitive: $this->isSensitive($action));
    }

    /**
     * Return why a decision with the effect and reason, on the action, is
     * reported, or null when the settings do not report it: the first reason,
     * in the order `DecisionReport` declares them, that applies to it and that
     * the settings report.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect  $effect
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null  $reason
     * @param  string  $action
     * @param  bool  $isPreview
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport|null
     */
    public function reportOf(DecisionEffect $effect, ?DecisionReason $reason, string $action, bool $isPreview): ?DecisionReport
    {
        return match (true) {
            $isPreview && $this->previews                                                                => DecisionReport::PREVIEW,
            $effect                                      === DecisionEffect::ALLOW                       => $this->allowReport($action),
            $this->insufficientAuthentication && $reason === DecisionReason::INSUFFICIENT_AUTHENTICATION => DecisionReport::INSUFFICIENT_AUTHENTICATION,
            $this->denials                                                                               => DecisionReport::DENIAL,
            default                                                                                      => null,
        };
    }

    /**
     * Determine whether the action is one of the sensitive actions.
     *
     * @param  string  $action
     * @return bool
     */
    public function isSensitive(string $action): bool
    {
        return isset($this->sensitive[$action]);
    }

    /**
     * Return why an allow of the action is reported, or null when it is not.
     *
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport|null
     */
    private function allowReport(string $action): ?DecisionReport
    {
        return match (true) {
            $this->allows === self::NONE => null,
            $this->isSensitive($action)  => DecisionReport::SENSITIVE_ACTION,
            $this->allows === self::ALL  => DecisionReport::ALL_ALLOWS,
            default                      => null,
        };
    }
}
