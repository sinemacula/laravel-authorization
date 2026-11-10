<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console\Support;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException;
use SineMacula\Laravel\Authorization\Reviews\ApplicationSelector;
use SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Reviews\Support\Definitions;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * What one `authorization:review` invocation asks (AUTHZ-11.6, N97): the
 * review, its reference, its scope, its window or actor, whether it lists
 * direct grants alone, and where its JSON Lines go, read from its arguments and
 * options.
 *
 * Each is read strictly, and anything it cannot read is refused with
 * `InvalidArgumentException`, whose message names the argument or option and
 * never a value it was given:
 *
 * - The query is `holders`, `holdings`, `expiring`, `granted_by` or `unused`.
 * - `holders` takes the role, permission or policy as `{type}:{key}`, its type
 *   `role`, `permission` or `policy`, or the definition's morph type; and
 *   `--direct-only` to list its direct grants alone. `holdings` takes the saved
 *   subject as `{morphType}:{key}`, which the console subject resolver resolves
 *   to its principal and identity, as `authorization:why` does. The other
 *   queries take no reference.
 * - `expiring` takes `--from` and `--until`, each a date and time read in UTC
 *   when it names no zone; `granted_by` takes `--actor` as `{morphType}:{key}`,
 *   matched exactly as stored; `unused` takes `--since`, read as `--from` is.
 *   No other query takes them.
 * - The scope is what applies in `--tenant`, or at the platform when no scope
 *   option is given; the grants rooted within `--rooted-within`; or
 *   `--everywhere`; at most one of the three. Each tenant is read as
 *   `authorization:why` reads `--tenant` (see `TenantOption`).
 * - `--application` is `none`, `any` or an application's name; omitted, it is
 *   `none` for what applies in a tenant or at the platform, and `any`
 *   otherwise, as `ReviewScope` takes them.
 * - `--output` names a file to write instead of the standard output, which must
 *   not exist unless `--force` is given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReviewInvocation
{
    /** @var array<string, \SineMacula\Laravel\Authorization\Enums\GrantTarget> The short names a holders reference may give its type by. */
    private const array TARGETS = ['role' => GrantTarget::ROLE, 'permission' => GrantTarget::PERMISSION, 'policy' => GrantTarget::POLICY];

    /**
     * Create a new invocation.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind  $kind
     * @param  string|null  $reference
     * @param  \SineMacula\Laravel\Authorization\Reviews\ReviewScope  $scope
     * @param  array<string, mixed>  $options
     * @param  string|null  $output
     * @param  bool  $isForced
     */
    private function __construct(

        /** The review asked for. */
        public ReviewKind $kind,

        /** The holders' target or the holdings' subject, as given; null for any other review. */
        public ?string $reference,

        /** The scope the review reads. */
        public ReviewScope $scope,

        /** The options given, read further for the review's own. */
        private array $options,

        /** The file the JSON Lines are written to; null for the standard output. */
        public ?string $output,

        /** Whether an existing output file is overwritten. */
        public bool $isForced,
    ) {}

    /**
     * Read the invocation from the command's arguments and options, refusing
     * any it cannot read.
     *
     * @param  array<string, mixed>  $arguments
     * @param  array<string, mixed>  $options
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function of(array $arguments, array $options): self
    {
        $kind      = self::kindOf($arguments['query'] ?? null);
        $reference = self::referenceOf($kind, $arguments['reference'] ?? null);

        self::refuseForeign($kind, $options);

        $output = $options['output'] ?? null;

        return new self($kind, $reference, self::scope($options), $options, \is_string($output) ? $output : null, ($options['force'] ?? false) === true);
    }

    /**
     * Return the review the invocation asks for, resolving the holdings'
     * subject through the console subject resolver.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver  $subjects
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewQuery
     *
     * @throws \InvalidArgumentException
     */
    public function query(ConsoleSubjectResolver $subjects): ReviewQuery
    {
        $options = $this->options;

        return match ($this->kind) {
            ReviewKind::HOLDERS    => ReviewQuery::holders(self::target((string) $this->reference), $this->scope, ($options['direct-only'] ?? false) === true),
            ReviewKind::HOLDINGS   => ReviewQuery::holdings(self::subject($subjects, (string) $this->reference), $this->scope),
            ReviewKind::EXPIRING   => ReviewQuery::expiring($this->scope, $this->instantOf('from'), $this->instantOf('until')),
            ReviewKind::GRANTED_BY => ReviewQuery::grantedBy(self::reference('actor', $options['actor'] ?? null), $this->scope),
            ReviewKind::UNUSED     => ReviewQuery::unused($this->scope, $this->instantOf('since')),
        };
    }

    /**
     * Return the instant the option names, read in UTC when it names no zone.
     *
     * @param  string  $option
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private function instantOf(string $option): CarbonImmutable
    {
        return self::instant($option, $this->options[$option] ?? null);
    }

    /**
     * Return the review the query argument names.
     *
     * @param  mixed  $query
     * @return \SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind
     *
     * @throws \InvalidArgumentException
     */
    private static function kindOf(mixed $query): ReviewKind
    {
        return ReviewKind::tryFrom(\is_string($query) ? $query : '') ?? throw new \InvalidArgumentException('The query must be holders, holdings, expiring, granted_by or unused.');
    }

    /**
     * Return the reference argument, which the holders and holdings reviews
     * need and the others refuse.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind  $kind
     * @param  mixed  $reference
     * @return string|null
     *
     * @throws \InvalidArgumentException
     */
    private static function referenceOf(ReviewKind $kind, mixed $reference): ?string
    {
        $given   = \is_string($reference) ? $reference : null;
        $isNamed = $kind === ReviewKind::HOLDERS || $kind === ReviewKind::HOLDINGS;

        if ($isNamed === ($given !== null)) {
            return $given;
        }

        $message = $isNamed ? 'The holders and holdings queries name a reference as {type}:{key}.' : 'The expiring, granted_by and unused queries take no reference.';

        throw new \InvalidArgumentException($message);
    }

    /**
     * Refuse an option the query does not take, and a missing one it needs:
     * `--direct-only` is the holders', `--from` and `--until` the expiries',
     * `--actor` an actor's grants', and `--since` the unused grants'.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\ReviewKind  $kind
     * @param  array<string, mixed>  $options
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function refuseForeign(ReviewKind $kind, array $options): void
    {
        $owners = [
            'direct-only' => ReviewKind::HOLDERS,
            'from'        => ReviewKind::EXPIRING,
            'until'       => ReviewKind::EXPIRING,
            'actor'       => ReviewKind::GRANTED_BY,
            'since'       => ReviewKind::UNUSED,
        ];

        foreach ($owners as $option => $owner) {
            $isGiven = ($options[$option] ?? null) !== null && ($options[$option] ?? null) !== false;

            if ($isGiven && $kind !== $owner) {
                throw new \InvalidArgumentException("The --{$option} option is taken by the {$owner->value} query alone.");
            }

            if (!$isGiven && $kind === $owner && $option !== 'direct-only') {
                throw new \InvalidArgumentException("The {$owner->value} query needs the --{$option} option.");
            }
        }
    }

    /**
     * Return the scope the options name: what applies in `--tenant`, or at the
     * platform with no scope option; the grants rooted within
     * `--rooted-within`; or every grant with `--everywhere`; in the application
     * `--application` selects.
     *
     * @param  array<string, mixed>  $options
     * @return \SineMacula\Laravel\Authorization\Reviews\ReviewScope
     *
     * @throws \InvalidArgumentException
     */
    private static function scope(array $options): ReviewScope
    {
        self::refuseSeveralScopes($options);

        $rooted      = $options['rooted-within'] ?? null;
        $application = self::application($options['application'] ?? null);

        return match (true) {
            $rooted !== null                           => ReviewScope::rootedWithin(TenantOption::reference('rooted-within', $rooted), $application),
            ($options['everywhere'] ?? false) === true => ReviewScope::everywhere($application),
            default                                    => ReviewScope::appliesIn(self::tenantOf($options['tenant'] ?? null), $application ?? ApplicationSelector::none()),
        };
    }

    /**
     * Refuse more than one of the scope options.
     *
     * @param  array<string, mixed>  $options
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function refuseSeveralScopes(array $options): void
    {
        $given = [($options['tenant'] ?? null) !== null, ($options['rooted-within'] ?? null) !== null, ($options['everywhere'] ?? false) === true];

        if (\count(\array_filter($given)) > 1) {
            throw new \InvalidArgumentException('Give at most one of the --tenant, --rooted-within and --everywhere options.');
        }
    }

    /**
     * Return the tenant `--tenant` names, or the platform for none.
     *
     * @param  mixed  $tenant
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \InvalidArgumentException
     */
    private static function tenantOf(mixed $tenant): ?Reference
    {
        return $tenant === null ? null : TenantOption::reference('tenant', $tenant);
    }

    /**
     * Return the application selector the option names: `none`, `any` or the
     * application named; null when it is not given.
     *
     * @param  mixed  $application
     * @return \SineMacula\Laravel\Authorization\Reviews\ApplicationSelector|null
     *
     * @throws \InvalidArgumentException
     */
    private static function application(mixed $application): ?ApplicationSelector
    {
        if ($application === null) {
            return null;
        }

        if (!\is_string($application) || $application === '') {
            throw new \InvalidArgumentException('The --application option must be none, any or an application\'s name.');
        }

        return match ($application) {
            ApplicationSelector::NONE => ApplicationSelector::none(),
            ApplicationSelector::ANY  => ApplicationSelector::any(),
            default                   => self::named($application),
        };
    }

    /**
     * Return the selector of the application named, refusing a name no grant
     * could hold.
     *
     * @param  string  $application
     * @return \SineMacula\Laravel\Authorization\Reviews\ApplicationSelector
     *
     * @throws \InvalidArgumentException
     */
    private static function named(string $application): ApplicationSelector
    {
        try {
            return ApplicationSelector::named($application);
        } catch (\InvalidArgumentException) {
            throw new \InvalidArgumentException('The --application option must be none, any or an application\'s name.');
        }
    }

    /**
     * Return the reference to the role, permission or policy the holders'
     * reference names: its type `role`, `permission` or `policy` read as that
     * definition's morph type, any other type as given.
     *
     * @param  string  $reference
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function target(string $reference): Reference
    {
        $target = self::reference('reference', $reference);
        $kind   = self::TARGETS[$target->type] ?? null;

        return $kind === null ? $target : new Reference(Definitions::morph($kind), $target->id);
    }

    /**
     * Resolve the holdings' subject through the console subject resolver,
     * refusing it by the reference argument's name alone, never the reference
     * given: as the resolver's refusal says, or, without naming the failure,
     * when the resolver fails other than by refusing it.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver  $subjects
     * @param  string  $reference
     * @return \SineMacula\Laravel\Authorization\Subject
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnresolvedSubjectException
     */
    private static function subject(ConsoleSubjectResolver $subjects, string $reference): Subject
    {
        try {
            return $subjects->resolve($reference);
        } catch (\Throwable $exception) {
            throw ($exception instanceof UnresolvedSubjectException ? $exception : UnresolvedSubjectException::unresolvable($exception))->namingOnly('reference');
        }
    }

    /**
     * Return the reference the value names as `{morphType}:{key}`, as given.
     *
     * @param  string  $name
     * @param  mixed  $value
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     *
     * @throws \InvalidArgumentException
     */
    private static function reference(string $name, mixed $value): Reference
    {
        $parts = \explode(':', \is_string($value) ? $value : '', 2);

        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new \InvalidArgumentException(($name === 'reference' ? 'The reference' : "The --{$name} option") . ' must be in the format {type}:{key} (e.g. role:1).');
        }

        return new Reference($parts[0], $parts[1]);
    }

    /**
     * Return the instant the option names, read in UTC when it names no zone.
     *
     * @param  string  $name
     * @param  mixed  $value
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private static function instant(string $name, mixed $value): CarbonImmutable
    {
        try {
            return CarbonImmutable::parse(\is_string($value) && \trim($value) !== '' ? $value : throw new \InvalidArgumentException, 'UTC');
        } catch (\Throwable) {
            throw new \InvalidArgumentException("The --{$name} option must be a date and time (e.g. 2026-12-01T00:00:00Z).");
        }
    }
}
