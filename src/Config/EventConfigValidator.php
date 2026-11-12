<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Evaluation\DecisionReporting;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;

/**
 * Validator and reader of the `authorization.events` config (BL-72), run by
 * `ConfigValidator`: which decisions `DecisionEvaluated` reports.
 *
 * The block sets no key but `decisions`, and `decisions` none but its five
 * settings (N116). `denials`, `insufficient_authentication` and `previews` are
 * switches, true or false (N117); `allows` is `all`, `sensitive` or `none`; and
 * `sensitive_actions` is a list of action names, each a catalogue action named
 * exactly, letters, digits and `_ - : .` with no wildcard. A setting left out
 * takes its default (every switch on, `sensitive`, no action), and one set to
 * null is refused, as is a block set to null.
 *
 * Whether each sensitive action is declared, by the package or the application,
 * is checked as `session.scopes` is: the bound `ActionCatalogue` is resolved
 * for it at boot, so the declared permissions are read then, and only when the
 * list names an action. `authorization:check` lists the list as checked at
 * boot, and the diagnostic boot runs that check with the others it leaves to
 * the boot.
 *
 * `reporting()` is the one way the package reads the settings at run time, once
 * for each batch of checks that reports its decisions, with plain type checks
 * and comparisons: a value changed after boot is refused there too, never read
 * as its default, while the name and the catalogue of a sensitive action are
 * checked at boot only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EventConfigValidator
{
    /** @var string The config key of the block. */
    public const string KEY = 'authorization.events';

    /** @var string The config key of the decision events' settings. */
    public const string DECISIONS = self::KEY . '.decisions';

    /** @var string The config key of the sensitive actions. */
    public const string SENSITIVE_ACTIONS = self::DECISIONS . '.sensitive_actions';

    /** @var list<string> The keys the block may set. */
    public const array KEYS = ['decisions'];

    /** @var list<string> The switches of the decision events, each on unless set. */
    public const array SWITCHES = ['denials', 'insufficient_authentication', 'previews'];

    /** @var list<string> The settings the decision events' block may set. */
    public const array SETTINGS = [...self::SWITCHES, 'allows', 'sensitive_actions'];

    /** @var string What a sensitive action is expected to be. */
    private const string ACTION = 'an action name, letters, digits and _ - : . with no wildcard';

    /**
     * Validate the supplied `events` config, throwing on the first failure.
     *
     * @param  mixed  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config, Container $container): void
    {
        $decisions = self::decisions(ConfigBlock::of(self::KEY, $config, self::KEYS));

        self::reporting($decisions);
        self::coverage(self::sensitiveActions(ConfigBlock::entry($decisions, 'sensitive_actions', [])), $container);
    }

    /**
     * Return the decision events' block of the `events` block, empty when it
     * sets none, refusing one that is not an array or that sets a key the
     * package does not define.
     *
     * @param  array<array-key, mixed>  $events
     * @return array<array-key, mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function decisions(array $events): array
    {
        return ConfigBlock::of(self::DECISIONS, ConfigBlock::entry($events, 'decisions', []), self::SETTINGS);
    }

    /**
     * Return what the decision events' settings report, read from the block as
     * the configuration holds it now, each setting left out taking its default,
     * refusing a value that is not one the setting takes. Only plain type
     * checks and comparisons are made.
     *
     * @param  array<array-key, mixed>  $decisions
     * @return \SineMacula\Laravel\Authorization\Evaluation\DecisionReporting
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function reporting(array $decisions): DecisionReporting
    {
        $switch = static fn (string $setting): bool => self::isReported($setting, ConfigBlock::entry($decisions, $setting, true));

        return new DecisionReporting(
            $switch('denials'),
            $switch('insufficient_authentication'),
            $switch('previews'),
            self::allows(ConfigBlock::entry($decisions, 'allows', DecisionReporting::SENSITIVE)),
            self::names(ConfigBlock::entry($decisions, 'sensitive_actions', [])),
        );
    }

    /**
     * Return whether the switch reports its kind of decision, refusing a value
     * that is not true or false.
     *
     * @param  string  $setting
     * @param  mixed  $value
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function isReported(string $setting, mixed $value): bool
    {
        if (\is_bool($value)) {
            return $value;
        }

        $reason = 'expected true or false, got ' . ConfigValidator::describe($value) . '.';

        throw new InvalidAuthorizationConfigException(self::DECISIONS . ".{$setting}", $reason, IssueCode::INVALID_TYPE, 'true or false', \get_debug_type($value));
    }

    /**
     * Return which allows are reported, refusing a value that is not `all`,
     * `sensitive` or `none`.
     *
     * @param  mixed  $value
     * @return string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function allows(mixed $value): string
    {
        if (\in_array($value, DecisionReporting::ALLOWS, true)) {
            /** @var string */
            return $value;
        }

        $expected = 'one of ' . \implode(', ', DecisionReporting::ALLOWS);
        $issue    = \is_string($value) ? IssueCode::INVALID_VALUE : IssueCode::INVALID_TYPE;

        $reason = "expected {$expected}, got " . ConfigValidator::describe($value) . '.';

        throw new InvalidAuthorizationConfigException(self::DECISIONS . '.allows', $reason, $issue, $expected, \get_debug_type($value));
    }

    /**
     * Return the sensitive actions, refusing a value that is not a list of
     * action names, each named exactly, with no wildcard.
     *
     * @param  mixed  $value
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function sensitiveActions(mixed $value): array
    {
        $actions = [];

        foreach (self::listOf($value) as $index => $name) {
            $actions[] = self::sensitiveAction($index, $name);
        }

        return $actions;
    }

    /**
     * Return the sensitive action at the index, refusing a value that is not an
     * action name, named exactly, with no wildcard.
     *
     * @param  int|string  $index
     * @param  mixed  $name
     * @return string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function sensitiveAction(int|string $index, mixed $name): string
    {
        $name = self::name($index, $name);

        if (Permission::isValidAuthorizationName($name) && !\str_contains($name, '*')) {
            return $name;
        }

        $reason = 'expected ' . self::ACTION . ', got ' . ConfigValidator::describe($name) . '.';

        throw new InvalidAuthorizationConfigException(self::SENSITIVE_ACTIONS . ".{$index}", $reason, IssueCode::INVALID_VALUE, self::ACTION, 'string');
    }

    /**
     * Validate that every sensitive action is one the package or the
     * application declares, reading the action catalogue only when there is an
     * action to check. The catalogue is built to read them, so this runs at
     * boot only.
     *
     * @param  list<string>  $actions
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function coverage(array $actions, Container $container): void
    {
        if ($actions === []) {
            return;
        }

        /** @var \SineMacula\Laravel\Authorization\Contracts\ActionCatalogue $catalogue */
        $catalogue = $container->make(ActionCatalogue::class);

        foreach ($actions as $index => $action) {
            if (!PackagePermissions::isDeclared($action) && !$catalogue->covers($action)) {
                $reason = "'{$action}' is no declared permission.";

                throw new InvalidAuthorizationConfigException(self::SENSITIVE_ACTIONS . ".{$index}", $reason, IssueCode::INVALID_VALUE, 'a declared permission', 'string');
            }
        }
    }

    /**
     * Return the list of names, refusing a value that is not a list of
     * non-empty strings, with plain type checks alone.
     *
     * @param  mixed  $value
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function names(mixed $value): array
    {
        $names = [];

        foreach (self::listOf($value) as $index => $name) {
            $names[] = self::name($index, $name);
        }

        return $names;
    }

    /**
     * Return the value, refusing one that is not a list.
     *
     * @param  mixed  $value
     * @return list<mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function listOf(mixed $value): array
    {
        if (\is_array($value) && \array_is_list($value)) {
            return $value;
        }

        $reason = 'expected a list of action names, got ' . ConfigValidator::describe($value) . '.';

        throw new InvalidAuthorizationConfigException(self::SENSITIVE_ACTIONS, $reason, IssueCode::INVALID_TYPE, 'a list of action names', \get_debug_type($value));
    }

    /**
     * Return the name at the index, refusing a value that is not a non-empty
     * string, with plain type checks alone.
     *
     * @param  int|string  $index
     * @param  mixed  $name
     * @return string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function name(int|string $index, mixed $name): string
    {
        if (\is_string($name) && $name !== '') {
            return $name;
        }

        $reason = 'expected ' . self::ACTION . ', got ' . ConfigValidator::describe($name) . '.';
        $issue  = \is_string($name) ? IssueCode::INVALID_VALUE : IssueCode::INVALID_TYPE;

        throw new InvalidAuthorizationConfigException(self::SENSITIVE_ACTIONS . ".{$index}", $reason, $issue, self::ACTION, \get_debug_type($name));
    }
}
