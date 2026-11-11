<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Diagnostics\IssueCollector;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException;

/**
 * Unit tests for running the checks of the configuration one setting at a time,
 * recording each refusal instead of stopping at the first.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IssueCollector::class)]
final class IssueCollectorTest extends TestCase
{
    /**
     * A check that passes records nothing; one that refuses records the
     * refusal; a refused permission declaration is recorded under the check's
     * path; anything else is internal, a type error among it.
     *
     * @return void
     */
    public function testEachFailureIsRecordedAsItsKind(): void
    {
        $collector = new IssueCollector;

        self::assertTrue($collector->verify('authorization.a', static fn (): bool => true));
        self::assertFalse($collector->verify(
            'authorization.b',
            static fn (): never => throw new InvalidAuthorizationConfigException('authorization.b.c', 'no', IssueCode::DUPLICATE),
        ));
        self::assertFalse($collector->verify('authorization.d', static fn (): never => throw new InvalidPermissionCatalogueException('x', 'no')));
        self::assertFalse($collector->verify('authorization.e', static fn (): never => throw new \TypeError('no')));

        self::assertSame([
            ['authorization.b.c', 'duplicate'],
            ['authorization.d', 'invalid_catalogue'],
            ['authorization.e', 'internal'],
        ], self::pathsAndCodes($collector));
    }

    /**
     * Attempting a check returns nothing when it passes, and the class of what
     * it threw when it fails, recording the failure as verifying does.
     *
     * @return void
     */
    public function testAnAttemptReturnsTheClassOfWhatItThrew(): void
    {
        $collector = new IssueCollector;

        self::assertNull($collector->attempt('authorization.a', static fn (): bool => true));
        self::assertSame(InvalidAuthorizationConfigException::class, $collector->attempt(
            'authorization.b',
            static fn (): never => throw new InvalidAuthorizationConfigException('authorization.b', 'no', IssueCode::INVALID_VALUE),
        ));
        self::assertSame(
            InvalidPermissionCatalogueException::class,
            $collector->attempt('authorization.c', static fn (): never => throw new InvalidPermissionCatalogueException('x', 'no')),
        );
        self::assertSame(\RuntimeException::class, $collector->attempt('authorization.d', static fn (): never => throw new \RuntimeException('secret')));

        self::assertSame([
            ['authorization.b', 'invalid_value'],
            ['authorization.c', 'invalid_catalogue'],
            ['authorization.d', 'internal'],
        ], self::pathsAndCodes($collector));
        self::assertSame(\RuntimeException::class, $collector->findings()->issues[2]->exception);
    }

    /**
     * A block that is not an array is refused and read as none; a block is
     * returned whole with each unknown key refused on its own.
     *
     * @return void
     */
    public function testABlockIsReadWithoutThrowing(): void
    {
        $collector = new IssueCollector;

        self::assertNull($collector->block('authorization.x', 'string', ['a']));
        self::assertSame(['a' => 1, 'b' => 2, 'c' => 3], $collector->block('authorization.y', ['a' => 1, 'b' => 2, 'c' => 3], ['a']));

        self::assertSame([
            ['authorization.x', 'invalid_type'],
            ['authorization.y.b', 'unknown_key'],
            ['authorization.y.c', 'unknown_key'],
        ], self::pathsAndCodes($collector));
    }

    /**
     * Each entry of an array is checked on its own, and whether every entry
     * passed is returned; a value that is not an array is refused.
     *
     * @return void
     */
    public function testEachEntryIsCheckedOnItsOwn(): void
    {
        $collector = new IssueCollector;
        $entry     = static function (int|string $key, mixed $value): void {
            if ($value !== 'ok') {
                throw new InvalidAuthorizationConfigException("authorization.list.{$key}", 'no', IssueCode::INVALID_VALUE);
            }
        };

        self::assertTrue($collector->verifyEntries('authorization.list', ['ok', 'ok'], $entry));
        self::assertFalse($collector->verifyEntries('authorization.list', ['bad', 'ok', 'bad'], $entry));
        self::assertFalse($collector->verifyEntries('authorization.list', 3, $entry));

        self::assertSame([
            ['authorization.list.0', 'invalid_value'],
            ['authorization.list.2', 'invalid_value'],
            ['authorization.list', 'invalid_type'],
        ], self::pathsAndCodes($collector));
    }

    /**
     * Skipped checks name what they depend on, a refused block skipping each of
     * its settings, and the settings left to the boot are listed in order.
     *
     * @return void
     */
    public function testSkippedAndBootCheckedSettingsAreRecorded(): void
    {
        $collector = new IssueCollector;

        $collector->skip('authorization.a', 'authorization.b');
        $collector->skipBlock('authorization.c', ['d', 'e']);
        $collector->checkedAtBoot('authorization.f');
        $collector->checkedAtBoot('authorization.g');

        $findings = $collector->findings();

        self::assertSame([['authorization.a', 'skipped'], ['authorization.c.d', 'skipped'], ['authorization.c.e', 'skipped']], self::pathsAndCodes($collector));
        self::assertSame(['authorization.b', 'authorization.c', 'authorization.c'], \array_map(static fn (ConfigIssue $issue): ?string => $issue->dependsOn, $findings->issues));
        self::assertSame(['authorization.f', 'authorization.g'], $findings->checkedAtBoot);
    }

    /**
     * Return the path and code of each issue recorded, in order.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\IssueCollector  $collector
     * @return list<array{string, string}>
     */
    private static function pathsAndCodes(IssueCollector $collector): array
    {
        return \array_map(static fn (ConfigIssue $issue): array => [$issue->path, $issue->code->value], $collector->findings()->issues);
    }
}
