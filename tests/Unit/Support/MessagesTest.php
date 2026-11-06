<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Contracts\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\Messages;

/**
 * Unit tests for `Messages`, which words the messages the package puts in front
 * of a client from the lines of its language file.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Messages::class)]
final class MessagesTest extends TestCase
{
    /**
     * The keys name the `denied` and `unauthenticated` lines of the package's
     * `authorization` language file.
     *
     * @return void
     */
    public function testTheKeysNameThePackagesLines(): void
    {
        self::assertSame('authorization::authorization.denied', Messages::DENIED);
        self::assertSame('authorization::authorization.unauthenticated', Messages::UNAUTHENTICATED);
    }

    /**
     * The line is the one the translator words for the key it is given.
     *
     * @return void
     */
    public function testTheLineIsTheTranslatorsLineForTheKey(): void
    {
        $translator = self::createStub(Translator::class);
        $translator->method('get')->willReturnMap([
            [Messages::DENIED, [], null, 'Action non autorisée.'],
            [Messages::UNAUTHENTICATED, [], null, 'Non authentifié.'],
        ]);

        self::assertSame('Action non autorisée.', Messages::line(Messages::DENIED, $translator));
        self::assertSame('Non authentifié.', Messages::line(Messages::UNAUTHENTICATED, $translator));
    }

    /**
     * Without a translator, or when the translator has no line for the key (it
     * answers with the key) or answers with something other than a line, there
     * is no line.
     *
     * @return void
     */
    public function testThereIsNoLineWithoutATranslatedString(): void
    {
        $missing = self::createStub(Translator::class);
        $missing->method('get')->willReturnArgument(0);

        $group = self::createStub(Translator::class);
        $group->method('get')->willReturn(['denied' => 'Denied.']);

        foreach ([null, $missing, $group] as $translator) {
            self::assertNull(Messages::line(Messages::DENIED, $translator));
        }
    }

    /**
     * The shipped English file holds a line for each key and nothing else: no
     * line per reason, since every denial carries the generic one.
     *
     * @return void
     */
    public function testTheLanguageFileHoldsOnlyTheLinesInUse(): void
    {
        /** @var array<string, string> $lines */
        $lines = require \dirname(__DIR__, 3) . '/lang/en/authorization.php';

        self::assertSame(['denied' => 'This action is unauthorized.', 'unauthenticated' => 'Unauthenticated.'], $lines);
    }
}
