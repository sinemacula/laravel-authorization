<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Config\BreakGlassConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Tests\Concerns\ReadsRefusedSettings;
use Tests\TestCase;

/**
 * Feature tests for the validation and reading of `authorization.break_glass`
 * (AUTHZ-11.7, N133): every setting optional with its default, each checked as
 * it is written, a key the package does not define refused, `enabled` true
 * refused while break-glass is not available, a role's maximum above the global
 * one refused, and the justification codes required once enabled.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(BreakGlassConfigValidator::class)]
final class BreakGlassConfigValidatorTest extends TestCase
{
    use ReadsRefusedSettings;

    /** @var string The path of the block. */
    private const string KEY = 'authorization.break_glass';

    /**
     * Every setting is optional, each taking its default, and every setting
     * written as the environment gives it is read as its value.
     *
     * @return void
     */
    public function testEverySettingIsOptionalAndTakesItsDefault(): void
    {
        $defaults = ['enabled' => false, 'max_minutes' => 60, 'roles' => [], 'justifications' => [], 'notes' => false, 'note_max_length' => 500];

        self::assertSame($defaults, BreakGlassConfigValidator::settings([]));
        self::assertSame(
            [
                'enabled'         => false,
                'max_minutes'     => 240,
                'roles'           => ['responder' => 30, 'db-admin' => 240],
                'justifications'  => ['incident', 'sev.1_outage-x'],
                'notes'           => true,
                'note_max_length' => 1,
            ],
            BreakGlassConfigValidator::settings([
                'enabled'         => false,
                'max_minutes'     => '240',
                'roles'           => ['responder' => ['max_minutes' => '30'], 'db-admin' => ['max_minutes' => null]],
                'justifications'  => ['incident', 'sev.1_outage-x'],
                'notes'           => true,
                'note_max_length' => '1',
            ]),
        );
        self::assertSame(['tenant:admin' => 1], BreakGlassConfigValidator::roles(['tenant:admin' => []], 1));

        BreakGlassConfigValidator::validate([]);
        BreakGlassConfigValidator::validate(['max_minutes' => 1, 'roles' => ['responder' => ['max_minutes' => 1]]]);
    }

    /**
     * The settings are read from the configuration through the same checks, so
     * one changed after boot is refused when it is read, never read as its
     * default.
     *
     * @return void
     */
    public function testTheReaderRefusesASettingChangedAfterBoot(): void
    {
        self::assertSame(60, BreakGlassConfigValidator::read()['max_minutes']);
        self::assertSame(15, BreakGlassConfigValidator::read(new Repository(['authorization' => ['break_glass' => ['max_minutes' => 15]]]))['max_minutes']);
        self::assertSame(500, BreakGlassConfigValidator::read(new Repository)['note_max_length']);

        \config(['authorization.break_glass.max_minutes' => '1h']);

        self::assertSame(
            [self::KEY . '.max_minutes', 'invalid_type', 'a whole number of at least 1', 'string'],
            self::refusedSetting(static fn () => BreakGlassConfigValidator::read()),
        );

        \config(['authorization.break_glass' => 'on']);

        try {
            BreakGlassConfigValidator::read();

            self::fail('A block that is not an array was read.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame(self::KEY, $exception->getConfigKey());
        }
    }

    /**
     * Return each block refused, with the path, the issue and the reason.
     *
     * @return iterable<string, array{mixed, string, string, string}>
     */
    public static function refused(): iterable
    {
        $key = self::KEY;

        yield 'not an array' => ['on', $key, 'invalid_type', 'expected an array, got \'on\' (string).'];
        yield 'null' => [null, $key, 'invalid_type', 'expected an array, got \'null\' (null).'];
        yield 'an unknown key' => [
            ['note' => true],
            "{$key}.note",
            'unknown_key',
            'unknown key \'note\'; expected one of enabled, max_minutes, roles, justifications, notes, note_max_length.',
        ];
        yield 'enabled null' => [['enabled' => null], "{$key}.enabled", 'invalid_type', 'expected true or false, got \'null\' (null).'];
        yield 'enabled as a string' => [['enabled' => 'true'], "{$key}.enabled", 'invalid_type', 'expected true or false, got \'true\' (string).'];
        yield 'enabled as a number' => [['enabled' => 1], "{$key}.enabled", 'invalid_type', 'expected true or false, got 1 (int).'];
        yield 'enabled true' => [['enabled' => true, 'justifications' => ['incident']], "{$key}.enabled", 'invalid_value', BreakGlassConfigValidator::UNAVAILABLE];
        yield 'max_minutes null' => [['max_minutes' => null], "{$key}.max_minutes", 'invalid_type', 'expected a whole number of at least 1, got \'null\' (null).'];
        yield 'max_minutes written loosely' => [['max_minutes' => '60m'], "{$key}.max_minutes", 'invalid_type', 'expected a whole number of at least 1, got \'60m\' (string).'];
        yield 'max_minutes a float' => [['max_minutes' => 1.5], "{$key}.max_minutes", 'invalid_type', 'expected a whole number of at least 1, got 1.5 (float).'];
        yield 'max_minutes zero' => [['max_minutes' => 0], "{$key}.max_minutes", 'out_of_range', 'expected a whole number of at least 1, got 0 (int).'];
        yield 'roles null' => [['roles' => null], "{$key}.roles", 'invalid_type', 'expected an array of role names mapped to their settings, got null.'];
        yield 'roles a list' => [
            ['roles' => ['responder']],
            "{$key}.roles.0",
            'invalid_value',
            'expected a role name (letters, digits, "_", "-", ":", "." and "*", of at most 191 characters), got 0 (int).',
        ];
        yield 'a role name that is not one' => [
            ['roles' => ['on call' => []]],
            "{$key}.roles.on call",
            'invalid_value',
            'expected a role name (letters, digits, "_", "-", ":", "." and "*", of at most 191 characters), got \'on call\' (string).',
        ];
        yield 'a role name too long' => [
            ['roles' => [\str_repeat('r', 192) => []]],
            "{$key}.roles." . \str_repeat('r', 192),
            'invalid_value',
            'expected a role name (letters, digits, "_", "-", ":", "." and "*", of at most 191 characters), got \'' . \str_repeat('r', 192) . '\' (string).',
        ];
        yield 'a role\'s settings not an array' => [['roles' => ['responder' => 30]], "{$key}.roles.responder", 'invalid_type', 'expected an array, got 30 (int).'];
        yield 'a role\'s unknown key' => [
            ['roles' => ['responder' => ['minutes' => 30]]],
            "{$key}.roles.responder.minutes",
            'unknown_key',
            'unknown key \'minutes\'; expected one of max_minutes.',
        ];
        yield 'a role\'s maximum written loosely' => [
            ['roles' => ['responder' => ['max_minutes' => '30m']]],
            "{$key}.roles.responder.max_minutes",
            'invalid_type',
            'expected a whole number of at least 1, got \'30m\' (string).',
        ];
        yield 'a role\'s maximum zero' => [
            ['roles' => ['responder' => ['max_minutes' => 0]]],
            "{$key}.roles.responder.max_minutes",
            'out_of_range',
            'expected a whole number of at least 1, got 0 (int).',
        ];
        yield 'a role\'s maximum above the global' => [
            ['max_minutes' => 60, 'roles' => ['responder' => ['max_minutes' => 61]]],
            "{$key}.roles.responder.max_minutes",
            'out_of_range',
            'a role\'s maximum of 61 minutes is longer than the global maximum of 60.',
        ];
        yield 'a role\'s maximum above the default global' => [
            ['roles' => ['responder' => ['max_minutes' => '61']]],
            "{$key}.roles.responder.max_minutes",
            'out_of_range',
            'a role\'s maximum of 61 minutes is longer than the global maximum of 60.',
        ];
        yield 'justifications null' => [['justifications' => null], "{$key}.justifications", 'invalid_type', 'expected a list of justification codes, got null.'];
        yield 'justifications a map' => [['justifications' => ['a' => 'incident']], "{$key}.justifications", 'invalid_type', 'expected a list of justification codes, got array.'];
        yield 'a code not a string' => [['justifications' => [7]], "{$key}.justifications.0", 'invalid_type', 'expected a justification code, got 7 (int).'];
        yield 'a code empty' => [
            ['justifications' => ['']],
            "{$key}.justifications.0",
            'invalid_value',
            'code \'\' is not a lower-case letter, then lower-case letters, digits, ".", "_" and "-", of at most 64 characters.',
        ];
        yield 'a code in upper case' => [
            ['justifications' => ['incident', 'Incident']],
            "{$key}.justifications.1",
            'invalid_value',
            'code \'Incident\' is not a lower-case letter, then lower-case letters, digits, ".", "_" and "-", of at most 64 characters.',
        ];
        yield 'a code with a space' => [
            ['justifications' => ['sev 1']],
            "{$key}.justifications.0",
            'invalid_value',
            'code \'sev 1\' is not a lower-case letter, then lower-case letters, digits, ".", "_" and "-", of at most 64 characters.',
        ];
        yield 'a code with a newline' => [
            ['justifications' => ["incident\n"]],
            "{$key}.justifications.0",
            'invalid_value',
            "code 'incident\n' is not a lower-case letter, then lower-case letters, digits, \".\", \"_\" and \"-\", of at most 64 characters.",
        ];
        yield 'a code too long' => [
            ['justifications' => [\str_repeat('c', 65)]],
            "{$key}.justifications.0",
            'out_of_range',
            'code \'' . \str_repeat('c', 65) . '\' is longer than 64 characters.',
        ];
        yield 'a code twice' => [
            ['justifications' => ['incident', 'outage', 'incident']],
            "{$key}.justifications.2",
            'duplicate',
            'code \'incident\' is already listed at index 0.',
        ];
        yield 'notes null' => [['notes' => null], "{$key}.notes", 'invalid_type', 'expected true or false, got \'null\' (null).'];
        yield 'notes as a string' => [['notes' => 'false'], "{$key}.notes", 'invalid_type', 'expected true or false, got \'false\' (string).'];
        yield 'note_max_length null' => [['note_max_length' => null], "{$key}.note_max_length", 'invalid_type', 'expected a whole number of at least 1, got \'null\' (null).'];
        yield 'note_max_length written loosely' => [
            ['note_max_length' => ' 500'],
            "{$key}.note_max_length",
            'invalid_type',
            'expected a whole number of at least 1, got \' 500\' (string).',
        ];
        yield 'note_max_length zero' => [['note_max_length' => '0'], "{$key}.note_max_length", 'out_of_range', 'expected a whole number of at least 1, got \'0\' (string).'];
    }

    /**
     * Each block refused is refused under its path, with its issue and why.
     *
     * @param  mixed  $config
     * @param  string  $path
     * @param  string  $issue
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refused')]
    public function testAMalformedBlockIsRefused(mixed $config, string $path, string $issue, string $reason): void
    {
        try {
            BreakGlassConfigValidator::validate($config);

            self::fail('The block was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame([$path, $issue, $reason], [$exception->getConfigKey(), $exception->getIssue()->value, $exception->getReason()]);
        }
    }

    /**
     * `enabled` true is refused, with the reason and what is expected, while
     * break-glass is not available, and accepted once it is; false is accepted
     * either way.
     *
     * @return void
     */
    public function testEnabledIsRefusedUntilBreakGlassIsAvailable(): void
    {
        self::assertFalse(BreakGlassConfigValidator::AVAILABLE);
        self::assertSame([self::KEY . '.enabled', 'invalid_value', 'false', 'bool'], self::refusedSetting(static fn () => BreakGlassConfigValidator::enabled(true)));
        self::assertSame('break-glass is not available until its audit trail ships; leave it disabled.', BreakGlassConfigValidator::UNAVAILABLE);
        self::assertTrue(BreakGlassConfigValidator::enabled(true, true));
        self::assertFalse(BreakGlassConfigValidator::enabled(false));
        self::assertFalse(BreakGlassConfigValidator::enabled(false, true));
        self::assertSame(
            [self::KEY . '.enabled', 'invalid_type', 'true or false', 'string'],
            self::refusedSetting(static fn () => BreakGlassConfigValidator::enabled('yes', true)),
        );
    }

    /**
     * The justification codes must list at least one code once break-glass is
     * enabled, and may list none while it is disabled; each code is checked on
     * its own, against those listed before it.
     *
     * @return void
     */
    public function testJustificationsAreRequiredOnceEnabled(): void
    {
        self::assertSame([], BreakGlassConfigValidator::justifications([], false));
        self::assertSame(['incident'], BreakGlassConfigValidator::justifications(['incident'], true));
        self::assertSame(['a', 'b'], BreakGlassConfigValidator::justifications(['a', 'b'], true));
        self::assertSame(
            [self::KEY . '.justifications', 'invalid_value', 'a list of at least one code', 'array'],
            self::refusedSetting(static fn () => BreakGlassConfigValidator::justifications([], true)),
        );
        self::assertSame(
            [self::KEY . '.justifications', 'invalid_type', 'a list of justification codes', 'string'],
            self::refusedSetting(static fn () => BreakGlassConfigValidator::justifications('incident', true)),
        );
        self::assertSame(\str_repeat('c', 64), BreakGlassConfigValidator::justification(0, \str_repeat('c', 64)));
        self::assertSame('incident', BreakGlassConfigValidator::justification(3, 'incident', ['outage' => 0]));
        self::assertSame(
            [self::KEY . '.justifications.3', 'duplicate', 'a lower-case letter, then lower-case letters, digits, ".", "_" and "-", of at most 64 characters', 'string'],
            self::refusedSetting(static fn () => BreakGlassConfigValidator::justification(3, 'outage', ['outage' => 0])),
        );
        self::assertSame(
            [self::KEY . '.justifications.0', 'invalid_type', 'a lower-case letter, then lower-case letters, digits, ".", "_" and "-", of at most 64 characters', 'null'],
            self::refusedSetting(static fn () => BreakGlassConfigValidator::justification(0, null)),
        );
    }

    /**
     * A role's maximum is its own, up to and including the global one, or the
     * global one when it sets none or null; each refusal is structured.
     *
     * @return void
     */
    public function testARolesMaximumIsBoundedByTheGlobalOne(): void
    {
        self::assertSame(60, BreakGlassConfigValidator::role('responder', ['max_minutes' => 60], 60));
        self::assertSame(1, BreakGlassConfigValidator::role('responder', ['max_minutes' => 1], 60));
        self::assertSame(60, BreakGlassConfigValidator::role('responder', ['max_minutes' => null], 60));
        self::assertSame(45, BreakGlassConfigValidator::role('responder', [], 45));
        self::assertSame(
            [self::KEY . '.roles.responder.max_minutes', 'out_of_range', 'a whole number from 1 to 60, or null', 'int'],
            self::refusedSetting(static fn () => BreakGlassConfigValidator::role('responder', ['max_minutes' => 61], 60)),
        );
        self::assertSame(
            [self::KEY . '.roles.7', 'invalid_value', 'a role name mapped to its settings', 'int'],
            self::refusedSetting(static fn () => BreakGlassConfigValidator::role(7, [], 60)),
        );
        self::assertSame(
            [self::KEY . '.roles', 'invalid_type', 'an array of role names mapped to their settings', 'string'],
            self::refusedSetting(static fn () => BreakGlassConfigValidator::roles('responder', 60)),
        );
    }

    /**
     * The global maximum, the note switch and the note's length each refuse
     * their own value, structured.
     *
     * @return void
     */
    public function testEachSettingIsCheckedOnItsOwn(): void
    {
        self::assertSame(1, BreakGlassConfigValidator::maxMinutes(1));
        self::assertSame(1440, BreakGlassConfigValidator::maxMinutes('1440'));
        self::assertTrue(BreakGlassConfigValidator::notes(true));
        self::assertFalse(BreakGlassConfigValidator::notes(false));
        self::assertSame(1, BreakGlassConfigValidator::noteMaxLength(1));
        self::assertSame(
            [self::KEY . '.max_minutes', 'out_of_range', 'a whole number of at least 1', 'int'],
            self::refusedSetting(static fn () => BreakGlassConfigValidator::maxMinutes(-5)),
        );
        self::assertSame([self::KEY . '.notes', 'invalid_type', 'true or false', 'int'], self::refusedSetting(static fn () => BreakGlassConfigValidator::notes(0)));
        self::assertSame(
            [self::KEY . '.note_max_length', 'out_of_range', 'a whole number of at least 1', 'int'],
            self::refusedSetting(static fn () => BreakGlassConfigValidator::noteMaxLength(0)),
        );
        self::assertSame(['enabled', 'max_minutes', 'roles', 'justifications', 'notes', 'note_max_length'], BreakGlassConfigValidator::SETTINGS);
        self::assertSame(['max_minutes'], BreakGlassConfigValidator::ROLE_SETTINGS);
        self::assertSame([60, 500, 64], [BreakGlassConfigValidator::MAX_MINUTES, BreakGlassConfigValidator::NOTE_MAX_LENGTH, BreakGlassConfigValidator::CODE_LENGTH]);
    }
}
