<?php

declare(strict_types = 1);

namespace Tests\Feature\Evaluation;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\DecisionReporting;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\TestCase;

/**
 * Feature tests for which decisions `DecisionEvaluated` reports and why: each
 * setting of `authorization.events.decisions` on and off, `allows` set to each
 * of its values, the order of the reasons, and the settings read as the
 * configuration holds them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DecisionReporting::class)]
final class DecisionReportingTest extends TestCase
{
    /** @var string The action listed as sensitive. */
    private const string SENSITIVE = 'posts:delete';

    /** @var string An action not listed as sensitive. */
    private const string ORDINARY = 'posts:read';

    /**
     * The defaults report every denial, every insufficient authentication and
     * every preview, and the allows of the sensitive actions alone.
     *
     * @return void
     */
    public function testTheDefaultsReportDenialsPreviewsAndSensitiveAllows(): void
    {
        $reporting = new DecisionReporting(sensitiveActions: [self::SENSITIVE]);

        self::assertSame(DecisionReport::DENIAL, $reporting->reportOf(DecisionEffect::DENY, DecisionReason::NO_MATCH, self::ORDINARY, false));
        self::assertSame(
            DecisionReport::INSUFFICIENT_AUTHENTICATION,
            $reporting->reportOf(DecisionEffect::DENY, DecisionReason::INSUFFICIENT_AUTHENTICATION, self::ORDINARY, false),
        );
        self::assertSame(DecisionReport::PREVIEW, $reporting->reportOf(DecisionEffect::ALLOW, null, self::ORDINARY, true));
        self::assertNull($reporting->reportOf(DecisionEffect::ALLOW, null, self::ORDINARY, false));
        self::assertSame(DecisionReport::SENSITIVE_ACTION, $reporting->reportOf(DecisionEffect::ALLOW, null, self::SENSITIVE, false));
        self::assertSame(['all', 'sensitive', 'none'], DecisionReporting::ALLOWS);
    }

    /**
     * Return each set of settings, a decision, and why it is reported, null for
     * one that is not.
     *
     * @return iterable<string, array{
     *     array<string, mixed>,
     *     \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect,
     *     \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null,
     *     string,
     *     bool,
     *     \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport|null,
     * }>
     */
    public static function reports(): iterable
    {
        $deny    = DecisionEffect::DENY;
        $allow   = DecisionEffect::ALLOW;
        $stepUp  = DecisionReason::INSUFFICIENT_AUTHENTICATION;
        $noMatch = DecisionReason::NO_MATCH;

        yield 'denials off: a denial is not reported' => [['denials' => false], $deny, $noMatch, self::ORDINARY, false, null];
        yield 'denials off: insufficient authentication still is' => [['denials' => false], $deny, $stepUp, self::ORDINARY, false, DecisionReport::INSUFFICIENT_AUTHENTICATION];
        yield 'denials off: a preview still is' => [['denials' => false], $deny, $noMatch, self::ORDINARY, true, DecisionReport::PREVIEW];
        yield 'insufficient authentication off: reported as a denial' => [['insufficient_authentication' => false], $deny, $stepUp, self::ORDINARY, false, DecisionReport::DENIAL];
        $neither = ['insufficient_authentication' => false, 'denials' => false];
        $nothing = ['denials' => false, 'insufficient_authentication' => false, 'previews' => false, 'allows' => 'none'];

        yield 'insufficient authentication and denials off: not reported' => [$neither, $deny, $stepUp, self::ORDINARY, false, null];
        yield 'previews off: a preview allow is not reported' => [['previews' => false], $allow, null, self::ORDINARY, true, null];
        yield 'previews off: a preview denial is reported as a denial' => [['previews' => false], $deny, $noMatch, self::ORDINARY, true, DecisionReport::DENIAL];
        yield 'previews off: a preview insufficient authentication' => [['previews' => false], $deny, $stepUp, self::ORDINARY, true, DecisionReport::INSUFFICIENT_AUTHENTICATION];
        yield 'previews off: a preview sensitive allow' => [['previews' => false], $allow, null, self::SENSITIVE, true, DecisionReport::SENSITIVE_ACTION];
        yield 'a preview before insufficient authentication' => [[], $deny, $stepUp, self::ORDINARY, true, DecisionReport::PREVIEW];
        yield 'a preview before a sensitive action' => [[], $allow, null, self::SENSITIVE, true, DecisionReport::PREVIEW];
        yield 'a denial of a sensitive action is a denial' => [[], $deny, $noMatch, self::SENSITIVE, false, DecisionReport::DENIAL];
        yield 'a denial of a sensitive action with denials off' => [['denials' => false], $deny, $noMatch, self::SENSITIVE, false, null];
        yield 'all: an ordinary allow' => [['allows' => 'all'], $allow, null, self::ORDINARY, false, DecisionReport::ALL_ALLOWS];
        yield 'all: a sensitive allow before all allows' => [['allows' => 'all'], $allow, null, self::SENSITIVE, false, DecisionReport::SENSITIVE_ACTION];
        yield 'all: a preview allow' => [['allows' => 'all'], $allow, null, self::ORDINARY, true, DecisionReport::PREVIEW];
        yield 'all with previews off: a preview allow' => [['allows' => 'all', 'previews' => false], $allow, null, self::ORDINARY, true, DecisionReport::ALL_ALLOWS];
        yield 'all: a denial' => [['allows' => 'all'], $deny, $noMatch, self::ORDINARY, false, DecisionReport::DENIAL];
        yield 'none: a sensitive allow' => [['allows' => 'none'], $allow, null, self::SENSITIVE, false, null];
        yield 'none: an ordinary allow' => [['allows' => 'none'], $allow, null, self::ORDINARY, false, null];
        yield 'none: a preview allow' => [['allows' => 'none'], $allow, null, self::SENSITIVE, true, DecisionReport::PREVIEW];
        yield 'none: a denial' => [['allows' => 'none'], $deny, $noMatch, self::SENSITIVE, false, DecisionReport::DENIAL];
        yield 'sensitive: an ordinary allow' => [['allows' => 'sensitive'], $allow, null, self::ORDINARY, false, null];
        yield 'everything off' => [$nothing, $deny, $stepUp, self::SENSITIVE, true, null];
    }

    /**
     * Each setting reports its kind of decision on its own, and a decision is
     * reported for the first reason, in the order the reasons are declared,
     * that applies to it and is reported.
     *
     * @param  array<string, mixed>  $settings
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect  $effect
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null  $reason
     * @param  string  $action
     * @param  bool  $isPreview
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport|null  $expected
     * @return void
     */
    #[DataProvider('reports')]
    public function testEachSettingReportsItsKindOfDecision(
        array $settings,
        DecisionEffect $effect,
        ?DecisionReason $reason,
        string $action,
        bool $isPreview,
        ?DecisionReport $expected,
    ): void {
        $this->config()->set('authorization.events.decisions', [...$settings, 'sensitive_actions' => [self::SENSITIVE]]);

        self::assertSame($expected, DecisionReporting::configured()->reportOf($effect, $reason, $action, $isPreview));
    }

    /**
     * Every setting left out takes its default, also when the configuration
     * sets no events block at all.
     *
     * @return void
     */
    public function testASettingLeftOutTakesItsDefault(): void
    {
        $this->config()->set('authorization.events', []);

        $reporting = DecisionReporting::configured();

        self::assertSame(DecisionReport::DENIAL, $reporting->reportOf(DecisionEffect::DENY, DecisionReason::NO_MATCH, self::ORDINARY, false));
        self::assertSame(
            DecisionReport::INSUFFICIENT_AUTHENTICATION,
            $reporting->reportOf(DecisionEffect::DENY, DecisionReason::INSUFFICIENT_AUTHENTICATION, self::ORDINARY, false),
        );
        self::assertSame(DecisionReport::PREVIEW, $reporting->reportOf(DecisionEffect::ALLOW, null, self::ORDINARY, true));
        self::assertNull($reporting->reportOf(DecisionEffect::ALLOW, null, self::ORDINARY, false));
        self::assertFalse($reporting->isSensitive(self::SENSITIVE));

        $config = $this->config()->get('authorization');

        unset($config['events']);

        $this->config()->set('authorization', $config);

        self::assertNull(DecisionReporting::configured()->reportOf(DecisionEffect::ALLOW, null, self::ORDINARY, false));
    }

    /**
     * A setting changed after boot to a value it does not take is refused as
     * the settings are read, never read as its default.
     *
     * @return void
     */
    public function testASettingChangedAfterBootIsRefusedWhenRead(): void
    {
        $this->config()->set('authorization.events.decisions.allows', 'some');

        try {
            DecisionReporting::configured();
            self::fail('An unknown value of allows was read.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.events.decisions.allows', $exception->getConfigKey());
        }

        $this->config()->set('authorization.events', 'all');

        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessage('Invalid authorization config at \'authorization.events\': expected an array, got \'all\' (string).');

        DecisionReporting::configured();
    }

    /**
     * Only the actions listed are sensitive, each named exactly.
     *
     * @return void
     */
    public function testOnlyTheListedActionsAreSensitive(): void
    {
        $reporting = new DecisionReporting(sensitiveActions: [self::SENSITIVE, 'roles:assign']);

        self::assertTrue($reporting->isSensitive(self::SENSITIVE));
        self::assertTrue($reporting->isSensitive('roles:assign'));
        self::assertFalse($reporting->isSensitive(self::ORDINARY));
        self::assertFalse($reporting->isSensitive('posts:*'));
        self::assertFalse($reporting->isSensitive('POSTS:DELETE'));
        self::assertFalse((new DecisionReporting)->isSensitive(self::SENSITIVE));
    }

    /**
     * `everything()` reports every decision for the most specific reason it
     * has.
     *
     * @return void
     */
    public function testEverythingReportsEveryDecision(): void
    {
        $everything = DecisionReporting::everything();

        self::assertSame(DecisionReport::ALL_ALLOWS, $everything->reportOf(DecisionEffect::ALLOW, null, self::ORDINARY, false));
        self::assertSame(DecisionReport::DENIAL, $everything->reportOf(DecisionEffect::DENY, DecisionReason::NO_MATCH, self::ORDINARY, false));
        self::assertSame(
            DecisionReport::INSUFFICIENT_AUTHENTICATION,
            $everything->reportOf(DecisionEffect::DENY, DecisionReason::INSUFFICIENT_AUTHENTICATION, self::ORDINARY, false),
        );
        self::assertSame(DecisionReport::PREVIEW, $everything->reportOf(DecisionEffect::DENY, DecisionReason::NO_MATCH, self::ORDINARY, true));
    }

    /**
     * A decision the settings report is made into its event, naming the reason,
     * whether its action is sensitive and its resource; one they do not report
     * is made into none.
     *
     * @return void
     */
    public function testAReportedDecisionIsMadeIntoItsEvent(): void
    {
        $reporting  = new DecisionReporting(sensitiveActions: [self::SENSITIVE]);
        $provenance = new DecisionProvenance(new Reference('user', '1'));
        $allow      = Decision::allow(DecisionStage::ALLOW);
        $resource   = ResourceReference::record('post', '42');

        $sensitive = $reporting->evaluated($provenance, self::SENSITIVE, $resource, $allow);
        $denial    = $reporting->evaluated($provenance, self::ORDINARY, null, Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT));

        self::assertNull($reporting->evaluated($provenance, self::ORDINARY, $resource, $allow));
        self::assertInstanceOf(DecisionEvaluated::class, $sensitive);
        self::assertSame(DecisionReport::SENSITIVE_ACTION, $sensitive->reportedBecause());
        self::assertTrue($sensitive->isSensitiveAction());
        self::assertSame('post:42', $sensitive->resource);
        self::assertSame(self::SENSITIVE, $sensitive->action);
        self::assertSame($provenance->subject, $sensitive->subject);
        self::assertInstanceOf(DecisionEvaluated::class, $denial);
        self::assertSame(DecisionReport::DENIAL, $denial->reportedBecause());
        self::assertFalse($denial->isSensitiveAction());
        self::assertNull($denial->resource);
    }

    /**
     * A preview's decision is reported as a preview, its previewer read from
     * the provenance.
     *
     * @return void
     */
    public function testAPreviewIsToldByItsPreviewer(): void
    {
        $reporting = new DecisionReporting;
        $allow     = Decision::allow(DecisionStage::ALLOW);
        $preview   = $reporting->evaluated(new DecisionProvenance(new Reference('user', '1'), null, new Reference('user', '2')), self::ORDINARY, null, $allow);

        self::assertInstanceOf(DecisionEvaluated::class, $preview);
        self::assertSame(DecisionReport::PREVIEW, $preview->reportedBecause());
        self::assertNull($reporting->evaluated(new DecisionProvenance(new Reference('user', '1')), self::ORDINARY, null, $allow));
    }

    /**
     * A refusal is made into its `AuthorizationFailed` whatever the settings,
     * for the reason it has with every setting on, saying whether its action is
     * sensitive.
     *
     * @return void
     */
    public function testARefusalIsReportedWhateverTheSettings(): void
    {
        $nothing    = new DecisionReporting(false, false, false, DecisionReporting::NONE, [self::SENSITIVE]);
        $provenance = new DecisionProvenance(new Reference('user', '1'));
        $stepUp     = Decision::deny(DecisionReason::INSUFFICIENT_AUTHENTICATION, DecisionStage::ALLOW);
        $denial     = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);

        $sensitive = $nothing->failed($provenance, self::SENSITIVE, ResourceReference::record('post', '42'), $denial);
        $ordinary  = $nothing->failed($provenance, self::ORDINARY, null, $stepUp);
        $preview   = $nothing->failed(new DecisionProvenance(new Reference('user', '1'), null, new Reference('user', '2')), self::ORDINARY, null, $denial);

        self::assertInstanceOf(AuthorizationFailed::class, $sensitive);
        self::assertSame(DecisionReport::DENIAL, $sensitive->reportedBecause());
        self::assertTrue($sensitive->isSensitiveAction());
        self::assertSame('post:42', $sensitive->resource);
        self::assertSame(self::SENSITIVE, $sensitive->action);
        self::assertSame(DecisionReport::INSUFFICIENT_AUTHENTICATION, $ordinary->reportedBecause());
        self::assertFalse($ordinary->isSensitiveAction());
        self::assertSame(DecisionReport::PREVIEW, $preview->reportedBecause());
    }

    /**
     * Return the configuration of the application.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): Repository
    {
        /** @var \Illuminate\Config\Repository */
        return $this->container()->make('config');
    }
}
