<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * PHPBench micro-benchmark for the `fnmatch` wildcard path.
 *
 * Every action / permission comparison in the package flows through
 * `fnmatch($pattern, $asked, FNM_NOESCAPE)` — statement matching,
 * `Role::hasPermission()`, and every `posts:*` style enum lookup.
 * The bench carves the call surface into four shapes so drift in
 * any single pattern class shows up under its own subject:
 *
 * - shallow prefix match        (`posts:*` vs `posts:create`);
 * - literal exact match         (`posts:create` vs `posts:create`);
 * - deep multi-segment match    (10-segment pattern with trailing `*`);
 * - miss on a non-matching set  (100 patterns, none match).
 *
 * The bench exercises the public `Statement::matches()` entry point
 * so the measured surface matches the production hot path exactly —
 * the raw `fnmatch()` call is not the only work a statement match
 * does, and benching it in isolation would hide any overhead drift
 * in the surrounding loop.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Bench\OutputTimeUnit('microseconds')]
final class WildcardMatchBench
{
    /** @var string Action string the shallow / literal subjects match against. */
    private const string ASKED_ACTION = 'posts:create';

    /**
     * @var \SineMacula\Laravel\Authorization\Evaluation\Statement statement carrying a single shallow prefix pattern
     *
     * @phpstan-ignore property.uninitialized, missingType.callable
     */
    private Statement $shallow;

    /**
     * @var \SineMacula\Laravel\Authorization\Evaluation\Statement statement carrying a single literal (no wildcards) action pattern
     *
     * @phpstan-ignore property.uninitialized, missingType.callable
     */
    private Statement $literal;

    /**
     * @var \SineMacula\Laravel\Authorization\Evaluation\Statement statement carrying a 10-segment-deep wildcard pattern
     *
     * @phpstan-ignore property.uninitialized, missingType.callable
     */
    private Statement $deep;

    /**
     * @var \SineMacula\Laravel\Authorization\Evaluation\Statement statement carrying 100 patterns that all miss the asked action
     *
     * @phpstan-ignore property.uninitialized, missingType.callable
     */
    private Statement $miss;

    /**
     * Bench setUp — materialise the four statement fixtures once
     * per iteration so revolution cost measures only the
     * `matches()` loop.
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->shallow = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['posts:*'],
        );

        $this->literal = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: [self::ASKED_ACTION],
        );

        // 10-segment deep glob — matches a `a:b:c:...:j` action.
        $this->deep = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['a:b:c:d:e:f:g:h:i:*'],
        );

        $patterns = [];

        for ($i = 0; $i < 100; $i++) {
            $patterns[] = "bucket_{$i}:*";
        }

        $this->miss = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: $patterns,
        );
    }

    /**
     * Benchmark: shallow prefix match — `posts:*` vs `posts:create`.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(10000)]
    public function benchShallowPrefixMatch(): void
    {
        $this->shallow->matches(self::ASKED_ACTION);
    }

    /**
     * Benchmark: literal exact match — `posts:create` vs `posts:create`.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(10000)]
    public function benchLiteralMatch(): void
    {
        $this->literal->matches(self::ASKED_ACTION);
    }

    /**
     * Benchmark: 10-segment deep pattern match.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(10000)]
    public function benchDeepPatternMatch(): void
    {
        $this->deep->matches('a:b:c:d:e:f:g:h:i:j');
    }

    /**
     * Benchmark: 100-pattern miss — worst-case walk of a wide
     * action list.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchHundredPatternMiss(): void
    {
        $this->miss->matches(self::ASKED_ACTION);
    }
}
