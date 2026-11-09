<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Support\GrantScope;

/**
 * Which application an access review reads grants for (AUTHZ-5.6), said
 * explicitly rather than by a null that could mean either of two things:
 *
 * - `none()`: a check with no application, where only the grants made for every
 *   application hold;
 * - `named()`: a check in that application, where the grants made for every
 *   application and those made for it hold;
 * - `any()`: a check in whichever application, so every grant holds, whatever
 *   application it was made for.
 *
 * A review's admission is decided in the named application, or with none for
 * the other two, where only authority held for every application counts, so a
 * review of every application needs authority in every application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApplicationSelector
{
    /** @var string The selection of the grants of a check with no application. */
    public const string NONE = 'none';

    /** @var string The selection of the grants of a check in one application. */
    public const string NAMED = 'named';

    /** @var string The selection of the grants of a check in whichever application. */
    public const string ANY = 'any';

    /**
     * Create a new application selector.
     *
     * @param  string|null  $application
     * @param  bool  $isAny
     */
    private function __construct(

        /** The application named; null for none, and for any. */
        public ?string $application,

        /** Whether the selection holds in whichever application. */
        public bool $isAny,
    ) {}

    /**
     * Return the selection of the grants of a check with no application.
     *
     * @return self
     */
    public static function none(): self
    {
        return new self(null, false);
    }

    /**
     * Return the selection of the grants of a check in the application.
     *
     * @param  string  $application
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function named(string $application): self
    {
        // A grant scope refuses an empty or oversized name, as the grant tables
        // do.
        return new self((new GrantScope(null, $application))->application, false);
    }

    /**
     * Return the selection of the grants of a check in whichever application.
     *
     * @return self
     */
    public static function any(): self
    {
        return new self(null, true);
    }

    /**
     * Return the name of the selection: `none`, `named` or `any`.
     *
     * @return string
     */
    public function selection(): string
    {
        return match (true) {
            $this->isAny                => self::ANY,
            $this->application === null => self::NONE,
            default                     => self::NAMED,
        };
    }

    /**
     * Limit a grant query to the rows of the table that hold in the selection.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TQuery  $query
     * @param  string  $table
     * @return TQuery
     */
    public function constrain(Builder $query, string $table): Builder
    {
        return $this->isAny ? $query : GrantApplications::only($query, $table, $this->application);
    }
}
