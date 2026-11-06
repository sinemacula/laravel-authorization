<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * The session caps of one check (AUTHZ-7.5): the scopes of the subject's
 * credential, as the action patterns they map to, and each set of actions the
 * caller passed to `Authorization::capped()`, outermost first.
 *
 * Every cap present must cover the action for the check to pass the session
 * stage, so the caps intersect; a cap covers an action when one of its patterns
 * is the action, or matches it with `fnmatch` and `FNM_NOESCAPE`, as statements
 * match actions. An empty cap covers nothing, so it allows nothing, while no
 * cap at all caps nothing. A cap grants nothing, and has no denies.
 *
 * Each cap carries the name the trace gives it: `credential` for the
 * credential's scopes, `credential:missing` for the empty cap that stands in
 * for a machine's missing scopes, and `capped[n]` for the n-th explicit cap.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionCaps
{
    /** @var string The name of the cap the credential's scopes make. */
    public const string CREDENTIAL = 'credential';

    /** @var string The name of the empty cap that stands in for a machine's missing credential scopes. */
    public const string MISSING_CREDENTIAL = 'credential:missing';

    /** @var string The name of an explicit cap, followed by its position, from 1. */
    public const string EXPLICIT = 'capped';

    /**
     * Create a new set of session caps.
     *
     * @param  list<array{string, list<string>}>  $caps
     */
    public function __construct(

        /** Each cap, as its name and the action patterns it covers. */
        public array $caps = [],
    ) {}

    /**
     * Make the caps of a check: the credential's, the action patterns its
     * scopes map to, when it carries a cap, and each explicit one, outermost
     * first. A machine whose credential carries no cap gets an empty one in its
     * place, which allows nothing: an explicit cap never stands in for its
     * missing scopes.
     *
     * @param  list<string>|null  $scopes
     * @param  list<list<string>>  $explicit
     * @param  bool  $isMachine
     * @return self
     */
    public static function of(?array $scopes, array $explicit = [], bool $isMachine = false): self
    {
        $caps = match (true) {
            $scopes !== null => [[self::CREDENTIAL, $scopes]],
            $isMachine       => [[self::MISSING_CREDENTIAL, []]],
            default          => [],
        };

        foreach ($explicit as $index => $actions) {
            $caps[] = [self::EXPLICIT . '[' . ($index + 1) . ']', $actions];
        }

        return new self($caps);
    }

    /**
     * Determine whether the patterns cover the action: one of them is the
     * action, or matches it.
     *
     * @param  list<string>  $patterns
     * @param  string  $action
     * @return bool
     */
    public static function covers(array $patterns, string $action): bool
    {
        foreach ($patterns as $pattern) {
            if ($pattern === $action || \fnmatch($pattern, $action, \FNM_NOESCAPE)) {
                return true;
            }
        }

        return false;
    }
}
