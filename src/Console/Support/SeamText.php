<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin;
use SineMacula\Laravel\Authorization\Diagnostics\SeamRow;

/**
 * A seam as `authorization:check` prints it as text: `[seam Contract]`, then
 * where its binding came from, what it builds, how long that lives, the
 * extenders registered on it, whether it was resolved before, and what a
 * sibling package declared of it when that no longer stands.
 *
 * A seam whose class custom code decides at first use is shown by where that
 * code is written, `supplied by custom code (file:line); class decided at first
 * use`, which is a note, never a failure.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SeamText
{
    /** @var string The namespace of the package's contracts, left out of their names. */
    private const string CONTRACTS = 'SineMacula\Laravel\Authorization\Contracts\\';

    /** @var array<string, string> How each origin is shown, where it names nothing more. */
    private const array ORIGINS = [
        Origin::PACKAGE_DEFAULT->value => 'package default',
        Origin::EARLIER_BINDING->value => 'bound before the package registered, which left it standing',
        Origin::LATER_BINDING->value   => 'bound after the package registered, over its binding',
        Origin::EXTERNAL->value        => 'bound outside the package',
        Origin::UNBOUND->value         => 'not bound; none',
    ];

    /**
     * Return the line of the seam.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRow  $seam
     * @return string
     */
    public static function line(SeamRow $seam): string
    {
        $contract = \str_starts_with($seam->contract, self::CONTRACTS) ? \substr($seam->contract, \strlen(self::CONTRACTS)) : $seam->contract;
        $parts    = [self::origin($seam), self::builds($seam)];

        if ($seam->lifetime !== null) {
            $parts[] = $seam->lifetime->value;
        }

        if ($seam->extenders !== []) {
            $parts[] = 'registered extenders: ' . \implode(', ', \array_map(ReportText::escape(...), $seam->extenders));
        }

        if ($seam->binding->previouslyResolved) {
            $parts[] = 'previously resolved';
        }

        $parts[] = $seam->origin === Origin::DECLARED ? null : self::declaration($seam);

        return ReportText::line("seam {$contract}", \implode('; ', \array_filter($parts, static fn (?string $part): bool => $part !== null)));
    }

    /**
     * Return what a seam supplied by custom code says: where the code is
     * written, and that it decides the class at first use.
     *
     * @param  string  $factory
     * @return string
     */
    public static function customCode(string $factory): string
    {
        return 'supplied by custom code (' . ReportText::escape($factory) . '); class decided at first use';
    }

    /**
     * Return where the seam's binding came from.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRow  $seam
     * @return string
     */
    private static function origin(SeamRow $seam): string
    {
        return match ($seam->origin) {
            Origin::CONFIGURED => 'configured in ' . ReportText::escape((string) $seam->record?->configKey),
            Origin::DECLARED   => 'declared by ' . ReportText::escape((string) $seam->declaration?->owner),
            Origin::DEFERRED   => 'deferred provider ' . ReportText::escape((string) $seam->binding->deferredProvider) . ', not loaded yet',
            Origin::ALIAS      => 'alias of ' . ReportText::escape((string) $seam->binding->alias),
            default            => self::ORIGINS[$seam->origin->value],
        };
    }

    /**
     * Return what the seam builds: its class, the classes a declared factory
     * may build and when it decides, or where the custom code deciding it is
     * written; or null when nothing is known of it.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRow  $seam
     * @return string|null
     */
    private static function builds(SeamRow $seam): ?string
    {
        $class = $seam->class();

        return match (true) {
            $class         !== null => ReportText::escape($class),
            $seam->factory !== null => self::customCode($seam->factory),
            default                 => self::factory($seam->classes, $seam->declaration?->decides),
        };
    }

    /**
     * Return the class a declaration names, or the classes a declared factory
     * may build and when it decides, or null when there are none.
     *
     * @param  list<string>  $classes
     * @param  string|null  $decides
     * @return string|null
     */
    private static function factory(array $classes, ?string $decides): ?string
    {
        $names = \implode(', ', \array_map(ReportText::escape(...), $classes));

        return match (true) {
            $classes === []                             => null,
            $decides === null && \count($classes) === 1 => $names,
            default                                     => "one of {$names}" . ($decides === null ? '' : ', decided ' . ReportText::escape($decides)),
        };
    }

    /**
     * Return what a sibling package declared of a seam whose binding is no
     * longer the declared one, or that declared no binding to compare, or null
     * when none declared it.
     *
     * @param  \SineMacula\Laravel\Authorization\Diagnostics\SeamRow  $seam
     * @return string|null
     */
    private static function declaration(SeamRow $seam): ?string
    {
        $declaration = $seam->declaration;

        if ($declaration === null) {
            return null;
        }

        $state = match ($declaration->standing($seam->binding->concrete)) {
            'overridden' => 'but overridden later',
            'standing'   => 'but an instance is bound over it',
            default      => 'unverified, as it named no binding',
        };

        return 'declared by ' . ReportText::escape($declaration->owner) . ' as ' . self::factory($declaration->classes, $declaration->decides) . ", {$state}";
    }
}
