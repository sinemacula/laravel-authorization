<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Unit tests for one issue the configuration check found, structured and never
 * a message.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigIssue::class)]
final class ConfigIssueTest extends TestCase
{
    /**
     * A refusal keeps its path, code, what was expected and the type found,
     * never its reason.
     *
     * @return void
     */
    public function testARefusalKeepsItsStructureAlone(): void
    {
        $issue = ConfigIssue::refused(new InvalidAuthorizationConfigException('authorization.x', 'got \'secret\'.', IssueCode::INVALID_TYPE, 'an array', 'string'));

        self::assertSame([
            'path'       => 'authorization.x',
            'code'       => 'invalid_type',
            'kind'       => 'refusal',
            'expected'   => 'an array',
            'got_type'   => 'string',
            'depends_on' => null,
            'exception'  => null,
        ], $issue->toArray());
    }

    /**
     * A skipped check names what it depends on, and is no refusal.
     *
     * @return void
     */
    public function testASkippedCheckNamesWhatItDependsOn(): void
    {
        $issue = ConfigIssue::skipped('authorization.cache.ttl', 'authorization.cache');

        self::assertSame('skipped', $issue->kind());
        self::assertSame('authorization.cache', $issue->toArray()['depends_on']);
        self::assertFalse($issue->code->isRefusal());
    }

    /**
     * An unforeseen failure keeps the exception's class, never its message.
     *
     * @return void
     */
    public function testAnUnforeseenFailureKeepsTheClassAlone(): void
    {
        $issue = ConfigIssue::internal('authorization.connection', new \TypeError('secret'));

        self::assertSame('internal', $issue->kind());
        self::assertSame(\TypeError::class, $issue->exception);
        self::assertStringNotContainsString('secret', (string) \json_encode($issue->toArray()));
    }
}
