<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics;

use SineMacula\Laravel\Authorization\Config\ConfigBlock;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException;

/**
 * Run the checks of the configuration one setting at a time, recording each
 * refusal instead of stopping at the first.
 *
 * A check that refuses the configuration is recorded as the refusal states it.
 * A refused permission declaration is recorded under the check's path. Anything
 * else a check throws, a `TypeError` among it, is a failure the package did not
 * foresee: it is recorded as `internal`, with the exception's class alone, and
 * makes the report incomplete.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IssueCollector
{
    /** @var list<\SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue> Every issue recorded, in order. */
    private array $issues = [];

    /** @var list<string> The paths whose building checks ran at boot and are not run again. */
    private array $checkedAtBoot = [];

    /**
     * Run the check of the setting under the path, recording what it refuses,
     * and return whether it passed.
     *
     * @param  string  $path
     * @param  \Closure(): mixed  $check
     * @return bool
     */
    public function verify(string $path, \Closure $check): bool
    {
        return $this->attempt($path, $check) === null;
    }

    /**
     * Run the check of the setting under the path, recording what it refuses,
     * and return the class of what it threw, or null when it passed.
     *
     * @param  string  $path
     * @param  \Closure(): mixed  $check
     * @return class-string<\Throwable>|null
     */
    public function attempt(string $path, \Closure $check): ?string
    {
        try {
            $check();

            return null;
        } catch (InvalidAuthorizationConfigException $refusal) {
            $this->issues[] = ConfigIssue::refused($refusal);
        } catch (InvalidPermissionCatalogueException $refusal) {
            $this->issues[] = new ConfigIssue($path, IssueCode::INVALID_CATALOGUE);
        } catch (\Throwable $refusal) {
            $this->issues[] = ConfigIssue::internal($path, $refusal);
        }

        return $refusal::class;
    }

    /**
     * Return the block under the path, recording a refusal when it is not an
     * array, and one for each key it sets that the package does not define,
     * each under its own path; null when it is not an array, the rest of the
     * block being still checked otherwise.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @param  list<string>  $keys
     * @return array<array-key, mixed>|null
     */
    public function block(string $path, mixed $value, array $keys): ?array
    {
        if (!\is_array($value)) {
            $this->issues[] = new ConfigIssue($path, IssueCode::INVALID_TYPE, ConfigBlock::ARRAY, \get_debug_type($value));

            return null;
        }

        foreach (ConfigBlock::unknownKeys($value, $keys) as $key) {
            $this->issues[] = ConfigIssue::refused(ConfigBlock::unknownKey($path, $key, $keys));
        }

        return $value;
    }

    /**
     * Check each entry of the array under the path on its own, recording a
     * refusal when the value is not an array, and return whether every entry
     * passed.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @param  \Closure(int|string, mixed): mixed  $entry
     * @return bool
     */
    public function verifyEntries(string $path, mixed $value, \Closure $entry): bool
    {
        if (!\is_array($value)) {
            $this->issues[] = new ConfigIssue($path, IssueCode::INVALID_TYPE, ConfigBlock::ARRAY, \get_debug_type($value));

            return false;
        }

        $passed = true;

        foreach ($value as $key => $item) {
            $passed = $this->verify("{$path}.{$key}", static function () use ($entry, $key, $item): void {
                $entry($key, $item);
            }) && $passed;
        }

        return $passed;
    }

    /**
     * Record that the check of the setting under the path was not run because
     * the setting it depends on was refused.
     *
     * @param  string  $path
     * @param  string  $dependsOn
     * @return void
     */
    public function skip(string $path, string $dependsOn): void
    {
        $this->issues[] = ConfigIssue::skipped($path, $dependsOn);
    }

    /**
     * Record that each setting of the block was not checked because the block
     * was refused.
     *
     * @param  string  $path
     * @param  list<string>  $keys
     * @return void
     */
    public function skipBlock(string $path, array $keys): void
    {
        foreach ($keys as $key) {
            $this->skip("{$path}.{$key}", $path);
        }
    }

    /**
     * Record that the checks of the setting under the path that build what it
     * names ran, and passed, as the application booted, and are not run again.
     *
     * @param  string  $path
     * @return void
     */
    public function checkedAtBoot(string $path): void
    {
        $this->checkedAtBoot[] = $path;
    }

    /**
     * Return what the checks found.
     *
     * @return \SineMacula\Laravel\Authorization\Diagnostics\ConfigFindings
     */
    public function findings(): ConfigFindings
    {
        return new ConfigFindings($this->issues, $this->checkedAtBoot);
    }
}
