<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Config\EventConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Evaluation\DecisionReporting;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReport;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use Tests\Concerns\ReadsRefusedSettings;
use Tests\Feature\Stubs\EmptyActionCatalogue;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\TestCase;

/**
 * Feature tests for `EventConfigValidator`, the validation of
 * `authorization.events`: its keys, the switches, `allows` and the sensitive
 * actions, named exactly and checked against the permissions the package and
 * the application declare, and the settings read at run time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(EventConfigValidator::class)]
final class EventConfigValidatorTest extends TestCase
{
    use ReadsRefusedSettings;

    /** @var string The path of the decision events' settings. */
    private const string DECISIONS = 'authorization.events.decisions';

    /** @var string What a sensitive action is expected to be. */
    private const string ACTION = 'an action name, letters, digits and _ - : . with no wildcard';

    /**
     * Declare the stub permission enum, `posts:create` and `posts:delete`, as
     * the application's permissions, before anything reads them, and check the
     * sensitive actions against the catalogue the package binds.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        $this->container()->forgetExtenders(ActionCatalogue::class);
        $this->container()->forgetScopedInstances();
    }

    /**
     * An empty block, a block of empty settings, the shipped settings and every
     * value each setting takes pass, a sensitive action named by the
     * application or the package included.
     *
     * @return void
     */
    public function testValidConfigsPass(): void
    {
        $this->expectNotToPerformAssertions();

        EventConfigValidator::validate([], $this->container());
        EventConfigValidator::validate(['decisions' => []], $this->container());
        EventConfigValidator::validate($this->authorizationConfig()['events'], $this->container());

        foreach (DecisionReporting::ALLOWS as $allows) {
            EventConfigValidator::validate(['decisions' => ['allows' => $allows]], $this->container());
        }

        EventConfigValidator::validate(['decisions' => [
            'denials'                     => false,
            'insufficient_authentication' => false,
            'previews'                    => false,
            'allows'                      => 'none',
            'sensitive_actions'           => ['posts:delete', 'posts:create', PackagePermissions::GUARDRAIL_MANAGE],
        ]], $this->container());
    }

    /**
     * The constants name the block, its keys and its settings.
     *
     * @return void
     */
    public function testTheConstantsNameTheSettings(): void
    {
        self::assertSame('authorization.events', EventConfigValidator::KEY);
        self::assertSame(self::DECISIONS, EventConfigValidator::DECISIONS);
        self::assertSame(self::DECISIONS . '.sensitive_actions', EventConfigValidator::SENSITIVE_ACTIONS);
        self::assertSame(['decisions'], EventConfigValidator::KEYS);
        self::assertSame(['denials', 'insufficient_authentication', 'previews'], EventConfigValidator::SWITCHES);
        self::assertSame(['denials', 'insufficient_authentication', 'previews', 'allows', 'sensitive_actions'], EventConfigValidator::SETTINGS);
    }

    /**
     * Provide `events` configs that are refused, with the key and the reason.
     *
     * @return iterable<string, array{0: mixed, 1: string, 2: string}>
     */
    public static function invalidConfigs(): iterable
    {
        $settings  = 'denials, insufficient_authentication, previews, allows, sensitive_actions';
        $switch    = 'expected true or false, got ';
        $allows    = 'expected one of all, sensitive, none, got ';
        $actions   = self::DECISIONS . '.sensitive_actions';
        $action    = 'expected ' . self::ACTION . ', got ';
        $decisions = static fn (array $block): array => ['decisions' => $block];

        yield 'events that are not an array' => ['all', 'authorization.events', 'expected an array, got \'all\' (string).'];
        yield 'null events' => [null, 'authorization.events', 'expected an array, got \'null\' (null).'];
        yield 'an unknown key' => [['decision' => []], 'authorization.events.decision', 'unknown key \'decision\'; expected one of decisions.'];
        yield 'decisions that are not an array' => [['decisions' => true], self::DECISIONS, 'expected an array, got true (bool).'];
        yield 'null decisions' => [['decisions' => null], self::DECISIONS, 'expected an array, got \'null\' (null).'];
        yield 'an unknown setting' => [$decisions(['allow' => 'all']), self::DECISIONS . '.allow', "unknown key 'allow'; expected one of {$settings}."];

        foreach (['denials', 'insufficient_authentication', 'previews'] as $setting) {
            yield "null {$setting}" => [$decisions([$setting => null]), self::DECISIONS . ".{$setting}", $switch . '\'null\' (null).'];
            yield "{$setting} as a number" => [$decisions([$setting => 1]), self::DECISIONS . ".{$setting}", $switch . '1 (int).'];
            yield "{$setting} as a string" => [$decisions([$setting => 'false']), self::DECISIONS . ".{$setting}", $switch . '\'false\' (string).'];
        }

        yield 'null allows' => [$decisions(['allows' => null]), self::DECISIONS . '.allows', $allows . '\'null\' (null).'];
        yield 'allows as a switch' => [$decisions(['allows' => true]), self::DECISIONS . '.allows', $allows . 'true (bool).'];
        yield 'an unknown allows' => [$decisions(['allows' => 'some']), self::DECISIONS . '.allows', $allows . '\'some\' (string).'];
        yield 'allows in capitals' => [$decisions(['allows' => 'ALL']), self::DECISIONS . '.allows', $allows . '\'ALL\' (string).'];
        yield 'null sensitive actions' => [$decisions(['sensitive_actions' => null]), $actions, 'expected a list of action names, got \'null\' (null).'];
        yield 'one sensitive action not listed' => [
            $decisions(['sensitive_actions' => 'posts:delete']),
            $actions,
            'expected a list of action names, got \'posts:delete\' (string).',
        ];
        yield 'sensitive actions keyed' => [$decisions(['sensitive_actions' => ['a' => 'posts:delete']]), $actions, 'expected a list of action names, got \'array\' (array).'];
        yield 'a sensitive action that is a number' => [$decisions(['sensitive_actions' => ['posts:delete', 7]]), $actions . '.1', $action . '7 (int).'];
        yield 'an empty sensitive action' => [$decisions(['sensitive_actions' => ['']]), $actions . '.0', $action . '\'\' (string).'];
        yield 'a sensitive wildcard' => [$decisions(['sensitive_actions' => ['posts:*']]), $actions . '.0', $action . '\'posts:*\' (string).'];
        yield 'a sensitive action with a space' => [$decisions(['sensitive_actions' => ['posts delete']]), $actions . '.0', $action . '\'posts delete\' (string).'];
        $long = \str_repeat('a', 192);

        yield 'a sensitive action too long' => [$decisions(['sensitive_actions' => [$long]]), $actions . '.0', $action . "'{$long}' (string)."];
        yield 'a sensitive action not declared' => [
            $decisions(['sensitive_actions' => ['posts:delete', 'posts:read']]),
            $actions . '.1',
            '\'posts:read\' is no declared permission.',
        ];
    }

    /**
     * An `events` config that is malformed, or names a sensitive action no one
     * declares, is refused under its key, with the reason.
     *
     * @param  mixed  $config
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidConfigs')]
    public function testInvalidConfigsAreRefused(mixed $config, string $key, string $reason): void
    {
        try {
            EventConfigValidator::validate($config, $this->container());
            self::fail('The config was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }

    /**
     * Each refusal is structured: its path, its code, what it expects and the
     * type it got.
     *
     * @return void
     */
    public function testEachRefusalIsStructured(): void
    {
        $actions = self::DECISIONS . '.sensitive_actions';

        self::assertSame(
            [self::DECISIONS . '.previews', 'invalid_type', 'true or false', 'int'],
            self::refusedSetting(static fn () => EventConfigValidator::isReported('previews', 0)),
        );
        self::assertSame(
            [self::DECISIONS . '.allows', 'invalid_value', 'one of all, sensitive, none', 'string'],
            self::refusedSetting(static fn () => EventConfigValidator::allows('every')),
        );
        self::assertSame(
            [self::DECISIONS . '.allows', 'invalid_type', 'one of all, sensitive, none', 'null'],
            self::refusedSetting(static fn () => EventConfigValidator::allows(null)),
        );
        self::assertSame([$actions, 'invalid_type', 'a list of action names', 'string'], self::refusedSetting(static fn () => EventConfigValidator::sensitiveActions('a')));
        self::assertSame([$actions . '.0', 'invalid_type', self::ACTION, 'int'], self::refusedSetting(static fn () => EventConfigValidator::sensitiveActions([1])));
        self::assertSame([$actions . '.0', 'invalid_value', self::ACTION, 'string'], self::refusedSetting(static fn () => EventConfigValidator::sensitiveActions([''])));
        self::assertSame([$actions . '.2', 'invalid_value', self::ACTION, 'string'], self::refusedSetting(static fn () => EventConfigValidator::sensitiveAction(2, 'a b')));
        self::assertSame([$actions . '.x', 'invalid_type', self::ACTION, 'bool'], self::refusedSetting(static fn () => EventConfigValidator::sensitiveAction('x', false)));

        $this->container()->instance(ActionCatalogue::class, new EmptyActionCatalogue);

        self::assertSame(
            [$actions . '.0', 'invalid_value', 'a declared permission', 'string'],
            self::refusedSetting(fn () => EventConfigValidator::coverage(['posts:delete'], $this->container())),
        );
    }

    /**
     * Each check returns the value it accepted.
     *
     * @return void
     */
    public function testEachCheckReturnsTheValue(): void
    {
        self::assertTrue(EventConfigValidator::isReported('denials', true));
        self::assertFalse(EventConfigValidator::isReported('denials', false));
        self::assertSame('none', EventConfigValidator::allows('none'));
        self::assertSame(['posts:delete', 'a.b_c-d:e'], EventConfigValidator::sensitiveActions(['posts:delete', 'a.b_c-d:e']));
        self::assertSame([], EventConfigValidator::sensitiveActions([]));
        self::assertSame('posts:delete', EventConfigValidator::sensitiveAction(0, 'posts:delete'));
        self::assertSame(['allows' => 'all'], EventConfigValidator::decisions(['decisions' => ['allows' => 'all']]));
        self::assertSame([], EventConfigValidator::decisions([]));
    }

    /**
     * The sensitive actions are checked against the bound action catalogue,
     * which is resolved only when the list names an action: an empty list
     * passes whatever the catalogue holds, and a catalogue declaring nothing
     * refuses every action but the package's own.
     *
     * @return void
     */
    public function testTheSensitiveActionsAreCheckedAgainstTheBoundCatalogueOnlyWhenNamed(): void
    {
        $resolved = new \ArrayObject;

        $this->container()->bind(ActionCatalogue::class, static function () use ($resolved): ActionCatalogue {
            $resolved->append(true);

            return new EmptyActionCatalogue;
        });

        EventConfigValidator::validate(['decisions' => ['sensitive_actions' => []]], $this->container());

        self::assertCount(0, $resolved);

        EventConfigValidator::validate(['decisions' => ['sensitive_actions' => [PackagePermissions::GUARDRAIL_MANAGE]]], $this->container());

        self::assertCount(1, $resolved);

        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessage('\'posts:create\' is no declared permission.');

        EventConfigValidator::validate(['decisions' => ['sensitive_actions' => ['posts:create']]], $this->container());
    }

    /**
     * The settings read at run time take their defaults when left out, are read
     * as set, and are refused with plain checks alone: a sensitive action that
     * is not a name is never matched rather than refused, while one that is not
     * a string, or a list that is not one, is refused.
     *
     * @return void
     */
    public function testTheSettingsReadAtRunTime(): void
    {
        $defaults = EventConfigValidator::reporting([]);
        $set      = EventConfigValidator::reporting([
            'denials'                     => false,
            'insufficient_authentication' => false,
            'previews'                    => false,
            'allows'                      => 'all',
            'sensitive_actions'           => ['posts:*', 'posts:delete'],
        ]);

        self::assertSame(DecisionReport::DENIAL, $defaults->reportOf(DecisionEffect::DENY, DecisionReason::NO_MATCH, 'posts:read', false));
        self::assertSame(DecisionReport::INSUFFICIENT_AUTHENTICATION, $defaults->reportOf(DecisionEffect::DENY, DecisionReason::INSUFFICIENT_AUTHENTICATION, 'posts:read', false));
        self::assertSame(DecisionReport::PREVIEW, $defaults->reportOf(DecisionEffect::ALLOW, null, 'posts:read', true));
        self::assertNull($defaults->reportOf(DecisionEffect::ALLOW, null, 'posts:read', false));
        self::assertNull($set->reportOf(DecisionEffect::DENY, DecisionReason::INSUFFICIENT_AUTHENTICATION, 'posts:read', true));
        self::assertSame(DecisionReport::ALL_ALLOWS, $set->reportOf(DecisionEffect::ALLOW, null, 'posts:read', true));
        self::assertTrue($set->isSensitive('posts:*'));
        self::assertTrue($set->isSensitive('posts:delete'));
        self::assertSame(
            [self::DECISIONS . '.sensitive_actions.0', 'invalid_type', self::ACTION, 'int'],
            self::refusedSetting(static fn () => EventConfigValidator::reporting(['sensitive_actions' => [1]])),
        );
        self::assertSame(
            [self::DECISIONS . '.sensitive_actions', 'invalid_type', 'a list of action names', 'null'],
            self::refusedSetting(static fn () => EventConfigValidator::reporting(['sensitive_actions' => null])),
        );
        self::assertSame(
            [self::DECISIONS . '.previews', 'invalid_type', 'true or false', 'null'],
            self::refusedSetting(static fn () => EventConfigValidator::reporting(['previews' => null])),
        );
        self::assertSame(
            [self::DECISIONS . '.allows', 'invalid_value', 'one of all, sensitive, none', 'string'],
            self::refusedSetting(static fn () => EventConfigValidator::reporting(['allows' => 'x'])),
        );
    }
}
