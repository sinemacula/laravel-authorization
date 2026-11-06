<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;

/**
 * Unit tests for the authentication requirement a statement states: the shape
 * of its operand, and the parts and maximum ages it holds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthenticationRequirement::class)]
final class AuthenticationRequirementTest extends TestCase
{
    /** @var string The reason a part's maximum age is refused, after the part. */
    private const string BAD_AGE = 'max_age must be a whole number of seconds, at least 1';

    /** @var string The refusal of an assurance level without a usable minimum. */
    private const string NO_MIN = 'requires min, a string that is not empty or blank';

    /** @var string The reason an operand maps no parts. */
    private const string NO_PARTS = 'requirement must map one or more parts (additional_verification, multifactor, phishing_resistant, assurance_level) to their options';

    /**
     * Provide operands that state a requirement.
     *
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function acceptedProvider(): iterable
    {
        yield 'additional verification' => [['additional_verification' => []]];
        yield 'multifactor' => [['multifactor' => []]];
        yield 'phishing resistant' => [['phishing_resistant' => []]];
        yield 'an assurance level' => [['assurance_level' => ['min' => 'aal2']]];
        yield 'a max age of one second' => [['multifactor' => ['max_age' => 1]]];
        yield 'a max age on every part' => [[
            'additional_verification' => ['max_age' => 60],
            'multifactor'             => ['max_age' => 900],
            'phishing_resistant'      => ['max_age' => 3600],
            'assurance_level'         => ['min' => 'aal3', 'max_age' => 86400],
        ]];
    }

    /**
     * An operand that states a requirement has no error, and builds it.
     *
     * @param  array<string, mixed>  $operand
     * @return void
     */
    #[DataProvider('acceptedProvider')]
    public function testAcceptsAWellFormedOperand(array $operand): void
    {
        self::assertNull(AuthenticationRequirement::errorOf($operand));
        self::assertSame(\array_keys($operand), AuthenticationRequirement::fromOperand($operand)->names());
    }

    /**
     * Provide operands that state no requirement, with the reason each is
     * refused.
     *
     * @return iterable<string, array{mixed, string}>
     */
    public static function refusedProvider(): iterable
    {
        yield 'a string' => ['multifactor', self::NO_PARTS];
        yield 'null' => [null, self::NO_PARTS];
        yield 'no parts' => [[], self::NO_PARTS];
        yield 'a list of parts' => [['multifactor'], self::NO_PARTS];
        yield 'an unknown part' => [['mfa' => []], 'requirement names an unknown part \'mfa\''];
        yield 'a numeric part' => [['multifactor' => [], 7 => []], 'requirement names an unknown part \'7\''];
        yield 'a part that is true' => [['multifactor' => true], 'requirement part \'multifactor\' must be an object of options'];
        yield 'a part that is a number' => [['multifactor' => 900], 'requirement part \'multifactor\' must be an object of options'];
        yield 'an unknown option' => [['multifactor' => ['age' => 900]], 'requirement part \'multifactor\' has unknown options: age'];
        yield 'min on another part' => [['multifactor' => ['min' => 'aal2']], 'requirement part \'multifactor\' has unknown options: min'];
        yield 'a list of options' => [['phishing_resistant' => [900]], 'requirement part \'phishing_resistant\' has unknown options: 0'];
        yield 'a max age of zero' => [['multifactor' => ['max_age' => 0]], 'requirement part \'multifactor\' max_age must be a whole number of seconds, at least 1'];
        yield 'a negative max age' => [['multifactor' => ['max_age' => -5]], 'requirement part \'multifactor\' max_age must be a whole number of seconds, at least 1'];
        yield 'a fractional max age' => [['multifactor' => ['max_age' => 1.5]], 'requirement part \'multifactor\' max_age must be a whole number of seconds, at least 1'];
        yield 'a numeric string max age' => [['multifactor' => ['max_age' => '900']], 'requirement part \'multifactor\' max_age must be a whole number of seconds, at least 1'];
        yield 'a true max age' => [['multifactor' => ['max_age' => true]], 'requirement part \'multifactor\' max_age must be a whole number of seconds, at least 1'];
        yield 'a null max age' => [['multifactor' => ['max_age' => null]], 'requirement part \'multifactor\' max_age must be a whole number of seconds, at least 1'];
        yield 'a level without min' => [['assurance_level' => []], 'requirement part \'assurance_level\' ' . self::NO_MIN];
        yield 'a level with a max age alone' => [['assurance_level' => ['max_age' => 60]], 'requirement part \'assurance_level\' ' . self::NO_MIN];
        yield 'an empty min' => [['assurance_level' => ['min' => '']], 'requirement part \'assurance_level\' ' . self::NO_MIN];
        yield 'a blank min' => [['assurance_level' => ['min' => '  ']], 'requirement part \'assurance_level\' ' . self::NO_MIN];
        yield 'a numeric min' => [['assurance_level' => ['min' => 2]], 'requirement part \'assurance_level\' ' . self::NO_MIN];
        yield 'a level with a bad max age' => [['assurance_level' => ['min' => 'aal2', 'max_age' => 0]], 'requirement part \'assurance_level\' ' . self::BAD_AGE];
        yield 'an unknown option on a level' => [['assurance_level' => ['min' => 'aal2', 'level' => 'x']], 'requirement part \'assurance_level\' has unknown options: level'];
        yield 'a fault after a good part' => [['multifactor' => [], 'phishing_resistant' => ['max_age' => 0]], 'requirement part \'phishing_resistant\' ' . self::BAD_AGE];
    }

    /**
     * An operand that states no requirement gives the exact reason, and is
     * refused when built.
     *
     * @param  mixed  $operand
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedProvider')]
    public function testRefusesAMalformedOperand(mixed $operand, string $reason): void
    {
        self::assertSame($reason, AuthenticationRequirement::errorOf($operand));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Authentication {$reason}.");

        AuthenticationRequirement::fromOperand($operand);
    }

    /**
     * The requirement keeps each part's maximum age and the minimum level, with
     * no age for a part that gives none.
     *
     * @return void
     */
    public function testKeepsEachPartsMaxAgeAndTheMinimumLevel(): void
    {
        $requirement = AuthenticationRequirement::fromOperand([
            'multifactor'     => ['max_age' => 900],
            'assurance_level' => ['min' => 'aal2'],
        ]);

        self::assertSame(['multifactor' => 900, 'assurance_level' => null], $requirement->parts);
        self::assertSame(900, $requirement->maxAge('multifactor'));
        self::assertNull($requirement->maxAge('assurance_level'));
        self::assertNull($requirement->maxAge('phishing_resistant'));
        self::assertSame('aal2', $requirement->minimumLevel);
    }

    /**
     * The parts are kept in their fixed order, whatever order they are written
     * in, so two requirements of the same parts are equal.
     *
     * @return void
     */
    public function testKeepsThePartsInTheirFixedOrder(): void
    {
        $requirement = AuthenticationRequirement::fromOperand([
            'assurance_level'         => ['min' => 'aal2'],
            'phishing_resistant'      => [],
            'additional_verification' => ['max_age' => 60],
        ]);

        self::assertSame(['additional_verification', 'phishing_resistant', 'assurance_level'], $requirement->names());
        self::assertEquals(new AuthenticationRequirement(['additional_verification' => 60, 'phishing_resistant' => null, 'assurance_level' => null], 'aal2'), $requirement);
    }

    /**
     * The minimum level of a requirement without the assurance level part is
     * null.
     *
     * @return void
     */
    public function testHasNoMinimumLevelWithoutTheAssuranceLevelPart(): void
    {
        self::assertNull(AuthenticationRequirement::fromOperand(['multifactor' => []])->minimumLevel);
    }

    /**
     * toArray() gives each part its maximum age, null for any, and the
     * assurance level its minimum.
     *
     * @return void
     */
    public function testToArrayGivesEachPartsOptions(): void
    {
        $requirement = new AuthenticationRequirement(['multifactor' => 900, 'phishing_resistant' => null, 'assurance_level' => 60], 'aal2');

        self::assertSame([
            'multifactor'        => ['max_age' => 900],
            'phishing_resistant' => ['max_age' => null],
            'assurance_level'    => ['max_age' => 60, 'min' => 'aal2'],
        ], $requirement->toArray());
    }

    /**
     * The constructor refuses what the operand would: no parts, an unknown
     * part, a bad age, a level without its minimum.
     *
     * @return iterable<string, array{array<string, int|null>, string|null, string}>
     */
    public static function refusedConstructionProvider(): iterable
    {
        yield 'no parts' => [[], null, 'Authentication ' . self::NO_PARTS . '.'];
        yield 'an unknown part' => [['mfa' => null], null, 'Authentication requirement names an unknown part \'mfa\'.'];
        yield 'a max age of zero' => [['multifactor' => 0], null, 'Authentication requirement part \'multifactor\' max_age must be a whole number of seconds, at least 1.'];
        yield 'a level without its minimum' => [['assurance_level' => null], null, 'Authentication requirement part \'assurance_level\' ' . self::NO_MIN . '.'];
        yield 'an empty minimum' => [['assurance_level' => null], '', 'Authentication requirement part \'assurance_level\' ' . self::NO_MIN . '.'];
        yield 'a minimum without the level' => [['multifactor' => null], 'aal2', 'Authentication requirement gives a minimum level without the assurance_level part.'];
        yield 'an unknown part and a stray minimum' => [['mfa' => null], 'aal2', 'Authentication requirement names an unknown part \'mfa\'.'];
    }

    /**
     * The constructor refuses a requirement the operand could not state.
     *
     * @param  array<string, int|null>  $parts
     * @param  string|null  $minimumLevel
     * @param  string  $message
     * @return void
     */
    #[DataProvider('refusedConstructionProvider')]
    public function testConstructionRefusesWhatNoOperandStates(array $parts, ?string $minimumLevel, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new AuthenticationRequirement($parts, $minimumLevel);
    }

    /**
     * The operator, its key and its parts are fixed.
     *
     * @return void
     */
    public function testTheOperatorKeyAndPartsAreFixed(): void
    {
        self::assertSame('authentication_requirement', AuthenticationRequirement::OPERATOR);
        self::assertSame('authentication', AuthenticationRequirement::KEY);
        self::assertSame('assurance_level', AuthenticationRequirement::ASSURANCE_LEVEL);
        self::assertSame(['additional_verification', 'multifactor', 'phishing_resistant', 'assurance_level'], AuthenticationRequirement::PARTS);
    }
}
