<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Read the structured refusal a configuration check throws: its path, its
 * stable code, what it expects and the type it got.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ReadsRefusedSettings
{
    /**
     * Run the check and return its refusal as path, code, expected and type
     * got, failing the test when it refused nothing.
     *
     * @param  \Closure(): mixed  $check
     * @return array{string, string, string|null, string|null}
     */
    protected static function refusedSetting(\Closure $check): array
    {
        try {
            $check();
        } catch (InvalidAuthorizationConfigException $refusal) {
            return [$refusal->getConfigKey(), $refusal->getIssue()->value, $refusal->getExpected(), $refusal->getGotType()];
        }

        self::fail('The setting was not refused.');
    }
}
