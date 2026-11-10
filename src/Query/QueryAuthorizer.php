<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Config\ConfigValue;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * Compiles the condition an authorized scope, `whereAuthorized()` or the
 * model-level `AuthorizedScope`, adds to a query: the rows it keeps are exactly
 * the rows `check()` allows (AUTHZ-10.1), or it refuses (AUTHZ-10.2, N64).
 *
 * The rows of the model are split into classes, each decided in one scope as
 * `check()` decides its rows (see `ScopeClasses` and `ResourceScope`): a
 * tenantless model's rows, or a tenant-bearing model's rows of no tenant, in
 * the request's scope; the rows within the active tenant's subtree in their own
 * tenant's scope, standing below the nearest anchor above them when they are
 * not one; and, when the subject holds the action platform-wide, every other
 * row of a tenant at platform scope, with its own tenant chain's guardrails and
 * the denies attached in its tenant chain.
 *
 * Each class is decided from the sources the decision pipeline itself gathers
 * in the class's scope, its principal selectors fresh for the class, and from
 * the policies attached to the type's records there (`RecordAttachments`): the
 * pipeline gathers a check on the type's records, `T:*`, which reads the
 * attachments of the type alone. The class's sources are compiled stage by
 * stage, as the policy evaluator weighs them (`DecisionFormula`), each
 * statement through `Statement::assess()` for its conditions and its resource
 * patterns compared with each row's key (`StatementScreen`), and the permission
 * held asked in the class's scope. A `withPolicies()` override replaces the
 * policies and reads no attachment, as it does for `check()`. A document that
 * cannot be read is refused, never compiled to no rows.
 *
 * The condition keeps the rows of each class whose decision allows: those whose
 * key identifies a record (not null, not empty, no NUL byte, as
 * `ResourceReferences` requires), and, where a statement weighed on every row
 * matches a pattern against the identifier, whose identifier `fnmatch()` would
 * not refuse as too long. A row of a tenant has a tenant of at most 191 bytes,
 * and a row of no tenant holds nothing in its tenant columns PHP would read as
 * other than a string, an integer or null, so no row it keeps is one `check()`
 * throws on. A guest, an inactive subject or a morph type with a NUL byte keeps
 * no row.
 *
 * Nothing is cached: every call compiles from the state at that instant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class QueryAuthorizer
{
    /** @var string The condition every row meets. */
    public const string EVERY_ROW = '1 = 1';

    /** @var string The condition no row meets. */
    public const string NO_ROW = '1 = 0';

    /** @var int The most policies one scope may attach to records when `authorization.query_scoping.max_attachments` is not set. */
    private const int MAX_ATTACHMENTS = 64;

    /**
     * Create a new query authorizer.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline  $pipeline
     * @param  \SineMacula\Laravel\Authorization\Context\CheckContextFactory|null  $contexts
     * @param  \SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver|null  $resourcePolicies
     * @param  \SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver|null  $guardrails
     */
    public function __construct(

        /** Gathers each class's sources, as it does for `check()`. */
        private DecisionPipeline $pipeline,

        /** Makes each check's context, and says which namespaces depend on the request alone; null for none. */
        private ?CheckContextFactory $contexts = null,

        /** Reads the policies attached to the type and its records; null when the pipeline reads none. */
        private ?ResourcePolicyResolver $resourcePolicies = null,

        /** Reads the guardrails of a tenant chain; null when the pipeline reads none. */
        private ?GuardrailResolver $guardrails = null,
    ) {}

    /**
     * Compile the condition that keeps the model's rows the subject may take
     * the action on, with the caller's context, or refuse.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $action
     * @param  array<string, mixed>  $context
     * @return string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    public function compile(?Subject $subject, Model $model, string $action, array $context = []): string
    {
        /** @var \SineMacula\Laravel\Authorization\Query\SchemaInspector $inspector */
        $inspector = Container::getInstance()->make(SchemaInspector::class);
        $shape     = ResourceShape::of($model, $action, $inspector);

        self::assertDeclaredResolver($shape, $action);

        if ($subject === null || SubjectGrants::isInactive($subject) || \str_contains($shape->type, "\0")) {
            return self::NO_ROW;
        }

        $classes     = ScopeClasses::of($shape, $subject, $action, $inspector);
        $screen      = new StatementScreen($action, $shape, $subject, $this->contexts);
        $attachments = $this->resourcePolicies === null ? null : new RecordAttachments($this->resourcePolicies, $shape, $inspector, self::attachmentLimit());
        $request     = new ClassRequest($shape, $subject, $action, $context, $screen, $attachments);
        $kept        = [];

        foreach ($classes as $class) {
            $decision = $class->membership === self::NO_ROW ? self::NO_ROW : $this->decideClass($request, $class);
            $kept[]   = Conditions::all([$class->membership, $decision]);
        }

        if ($screen->refusals() !== []) {
            throw new QueryScopeRefusedException($action, $shape->type, $screen->refusals());
        }

        return Conditions::all([$shape->dialect->keyGuard($shape->key, $shape->keyKind, $shape->isIntegerCast), Conditions::any($kept)]);
    }

    /**
     * Refuse a bound resource tenant resolver other than the declared one,
     * which reads a declared model's tenant as the scope compares it.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  string  $action
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private static function assertDeclaredResolver(ResourceShape $shape, string $action): void
    {
        $resolver = Container::getInstance()->make(ResourceTenantResolver::class);

        if (!$resolver instanceof DeclaredResourceTenant) {
            throw QueryScopeRefusedException::of($action, $shape->type, new Refusal(RefusalReason::TENANT_RESOLVER, null, null, $resolver::class));
        }
    }

    /**
     * Return the condition a row of the class meets when `check()` allows it,
     * decided in the scope `check()` decides its rows in: the request's for a
     * class of no tenant, its tenant's, standing below it when asked, or the
     * platform's for rows admitted from outside.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ClassRequest  $request
     * @param  \SineMacula\Laravel\Authorization\Query\ScopeClass  $class
     * @return string
     */
    private function decideClass(ClassRequest $request, ScopeClass $class): string
    {
        $application = TenantScope::currentApplication();

        return match (true) {
            $class->isAdmitted      => TenantScope::within(null, $application, fn (): string => $this->decideAdmitted($request, $class)),
            $class->tenant === null => $this->decideIn($request, null),
            default                 => TenantScope::within($class->tenant, $application, fn (): string => $this->decideIn($request, $class->tenant), $class->isBelow),
        };
    }

    /**
     * Return the condition a row of a class decided in the current scope meets
     * when `check()` allows it, from the sources gathered there and the
     * policies attached to records there; none, keeping the refusal, when a
     * document cannot be read.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ClassRequest  $request
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return string
     */
    private function decideIn(ClassRequest $request, ?Reference $tenant): string
    {
        try {
            $sources = $this->pipeline->sources($request->subject, $request->action, ResourceReference::record($request->shape->type, '*', $tenant), $request->context);
        } catch (InvalidPolicyDocumentException) {
            $request->screen->refuse(new Refusal(RefusalReason::INVALID_POLICY));

            return self::NO_ROW;
        }

        return $this->decided($request, $sources, $request->attachments?->inScope($request->action, $request->screen, false) ?? []);
    }

    /**
     * Return the condition a row admitted from outside the request's scope
     * meets when `check()` allows it, at platform scope: from the platform's
     * sources and the policies attached to records there, with the guardrails
     * of the class's tenant chain in place of the platform's alone, and the
     * denies attached in its tenant chain, to the type and to its records,
     * added; none, keeping the refusal, when a document cannot be read.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ClassRequest  $request
     * @param  \SineMacula\Laravel\Authorization\Query\ScopeClass  $class
     * @return string
     */
    private function decideAdmitted(ClassRequest $request, ScopeClass $class): string
    {
        $tenant = $class->tenant;

        try {
            $sources  = $this->pipeline->sources($request->subject, $request->action, ResourceReference::record($request->shape->type, '*'), $request->context);
            $isCapped = $sources->guardrails !== null;
            $own      = $tenant === null
                ? [[], $sources->guardrails, []]
                : TenantScope::within($tenant, TenantScope::currentApplication(), fn (): array => $this->ownSourcesOf($request, $tenant, $isCapped), $class->isBelow);
        } catch (InvalidPolicyDocumentException) {
            $request->screen->refuse(new Refusal(RefusalReason::INVALID_POLICY));

            return self::NO_ROW;
        }

        [$denies, $guardrails, $attached] = $own;

        $admitted = new CheckSources([...$sources->policies, ...$denies], $guardrails, $sources->boundaries, $sources->context, $sources->permission, $sources->session);

        return $this->decided($request, $admitted, [...$request->attachments?->inScope($request->action, $request->screen, false) ?? [], ...$attached]);
    }

    /**
     * Return what an admitted row's own tenant chain adds, read in its scope:
     * the deny statements of the policies attached to the type there, the
     * guardrails there unless the check is exempt from them, and the policies
     * attached to records there, their denies alone counting.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ClassRequest  $request
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  bool  $isCapped
     * @return array{
     *     list<\SineMacula\Laravel\Authorization\Evaluation\Policy>,
     *     array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>|null,
     *     list<array{\SineMacula\Laravel\Authorization\Evaluation\Policy, string, bool}>
     * }
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private function ownSourcesOf(ClassRequest $request, Reference $tenant, bool $isCapped): array
    {
        $resource   = ResourceReference::record($request->shape->type, '*', $tenant);
        $denies     = SubjectGrants::denialsOf($this->resourcePolicies?->policiesFor($resource) ?? []);
        $guardrails = $isCapped ? ($this->guardrails?->guardrailsFor($resource) ?? []) : null;

        return [$denies, $guardrails, $request->attachments?->inScope($request->action, $request->screen, true) ?? []];
    }

    /**
     * Return the condition a row of the class meets when the sources allow it:
     * the compiled decision and, when a statement weighed on every row matches
     * a pattern against the identifier, that the row's key is short enough for
     * `fnmatch()`. The permission held is asked in the current scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ClassRequest  $request
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckSources  $sources
     * @param  list<array{\SineMacula\Laravel\Authorization\Evaluation\Policy, string, bool}>  $attached
     * @return string
     */
    private function decided(ClassRequest $request, CheckSources $sources, array $attached): string
    {
        [$decision, $isPatterned] = DecisionFormula::of($request->action, $request->screen, $sources, ($sources->permission)() !== null, $attached);

        return Conditions::all([$decision, $isPatterned ? self::shortKey($request->shape) : self::EVERY_ROW]);
    }

    /**
     * Return the condition a row's key meets when its identifier is short
     * enough for `fnmatch()`; every row's key is, when its kind bounds its
     * length.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @return string
     */
    private static function shortKey(ResourceShape $shape): string
    {
        $length = $shape->dialect->keyLength($shape->key, $shape->keyKind, $shape->isIntegerCast);

        return $length === null ? self::EVERY_ROW : $length . ' <= ' . (\PHP_MAXPATHLEN - \strlen($shape->type) - 2);
    }

    /**
     * Return the most policies one scope may attach to records of the type:
     * `authorization.query_scoping.max_attachments`, or the default when it is
     * left out, refusing one that is not a whole number of at least one.
     *
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function attachmentLimit(): int
    {
        return ConfigValue::integer('query_scoping.max_attachments', self::MAX_ATTACHMENTS, 1);
    }
}
