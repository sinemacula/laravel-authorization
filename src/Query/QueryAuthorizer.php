<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceScope;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Compiles the condition `whereAuthorized()` adds to a query: the rows it keeps
 * are exactly the rows `check()` allows (AUTHZ-10.1), or it refuses
 * (AUTHZ-10.2, N64). Part 1 compiles only statements over the whole type (N68).
 *
 * The rows of the model are split into classes, each decided in one scope as
 * `check()` decides its rows (see `ResourceScope`): a tenantless model's rows,
 * or a tenant-bearing model's rows of no tenant, in the request's scope; and,
 * when a tenant is active, the rows of that tenant exactly, in its own scope.
 * Every other row of a tenant-bearing model is denied by `check()` as
 * `tenant_scope`, so it is left out; that holds only with the flat tenant tree
 * and when the subject holds no platform-wide grant of the action, which would
 * admit it, so anything else is refused (part 2 adds them).
 *
 * Each class is decided once, through the decision pipeline itself, from the
 * sources it gathers in the class's scope, its principal selectors fresh for
 * the class: the pipeline decides a check on the type's records, `T:*`, which
 * reads the attachments of the type alone. That decision is every row's in the
 * class when no material statement compares a key, which the statement screen
 * proves for each, and when no policy attached to a record of the type names
 * the action, which is refused otherwise (unless a `withPolicies()` override
 * replaces the attached policies, as it does for `check()`). A document that
 * cannot be read is refused too, never compiled to no rows.
 *
 * The condition keeps the rows of each class whose decision allows: those whose
 * key identifies a record (not null, not empty, no NUL byte, as
 * `ResourceReferences` requires), and, where a material statement's pattern is
 * matched against the identifier, whose identifier `fnmatch()` would not refuse
 * as too long. A row of a tenant has a tenant of at most 191 bytes, the active
 * one's, so no row it keeps is one `check()` throws on. A guest, an inactive
 * subject or a morph type with a NUL byte keeps no row.
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

    /**
     * Create a new query authorizer.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionPipeline  $pipeline
     * @param  \SineMacula\Laravel\Authorization\Context\CheckContextFactory|null  $contexts
     * @param  \SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver|null  $resourcePolicies
     */
    public function __construct(

        /** Gathers and weighs each class's sources, as it does for `check()`. */
        private DecisionPipeline $pipeline,

        /** Makes each check's context, and says which namespaces depend on the request alone; null for none. */
        private ?CheckContextFactory $contexts = null,

        /** Reads the policies attached to the type's records; null when the pipeline reads none. */
        private ?ResourcePolicyResolver $resourcePolicies = null,
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

        $classes = self::classesOf($shape, $subject, $action);
        $screen  = new StatementScreen($action, $shape->type, $subject, $this->contexts);
        $kept    = [];

        $this->screenAttachments($shape, $action, $screen);

        foreach ($classes as [$tenant, $membership]) {
            $kept[] = self::all([$membership, $this->decideClass($shape, $subject, $action, $context, $tenant, $screen)]);
        }

        if ($screen->refusals() !== []) {
            throw new QueryScopeRefusedException($action, $shape->type, $screen->refusals());
        }

        return self::all([$shape->dialect->keyGuard($shape->key, $shape->keyKind, $shape->isIntegerCast), self::any($kept)]);
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
     * Return each class of rows, as the tenant its rows are decided as having
     * and the condition a row of it meets: every row of a tenantless model;
     * else the rows of no tenant and, when a tenant is active, the rows of it.
     * A tenant-bearing model is refused unless the tree is flat and the subject
     * holds no platform-wide grant of the action.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @return list<array{\SineMacula\Laravel\Authorization\Support\Reference|null, string}>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    private static function classesOf(ResourceShape $shape, Subject $subject, string $action): array
    {
        if ($shape->idColumn === null) {
            return [[null, self::EVERY_ROW]];
        }

        // A platform-wide grant of the action admits rows of every tenant, as
        // `ResourceScope` admits them.
        $isAdmitted = static fn (): bool => SubjectGrants::holdsPermission($subject, $action);
        $reason     = match (true) {
            !TenantChain::tree() instanceof FlatTenantTree                            => RefusalReason::TENANT_TREE,
            TenantScope::within(null, TenantScope::currentApplication(), $isAdmitted) => RefusalReason::PLATFORM_ADMISSION,
            default                                                                   => null,
        };

        if ($reason !== null) {
            throw QueryScopeRefusedException::of($action, $shape->type, new Refusal($reason));
        }

        $active   = TenantScope::currentChain()->tenant();
        $tenantOf = $shape->typeColumn === null ? "{$shape->idColumn} IS NULL" : "({$shape->typeColumn} IS NULL OR {$shape->idColumn} IS NULL)";

        return $active === null ? [[null, $tenantOf]] : [[null, $tenantOf], [$active, self::ofTenant($shape, $active)]];
    }

    /**
     * Return the condition a row of the tenant meets: its tenant columns hold
     * exactly the tenant's type and key, byte for byte.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return string
     */
    private static function ofTenant(ResourceShape $shape, Reference $tenant): string
    {
        /** @var string $idColumn */
        $idColumn = $shape->idColumn;
        $isFixed  = $shape->tenancy->type === $tenant->type ? self::EVERY_ROW : self::NO_ROW;
        $isType   = $shape->typeColumn    === null ? $isFixed : $shape->dialect->equalsBytes($shape->typeColumn, $tenant->type);

        return self::all([$isType, $shape->dialect->equalsBytes($idColumn, $tenant->id)]);
    }

    /**
     * Refuse the query when a policy attached to a record of the type names the
     * action, or cannot be read: part 1 compiles no record's attachment. A
     * `withPolicies()` override reads no attachment, so nothing is refused.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Query\StatementScreen  $screen
     * @return void
     */
    private function screenAttachments(ResourceShape $shape, string $action, StatementScreen $screen): void
    {
        try {
            $policies = $this->resourcePolicies?->recordPolicies($shape->type) ?? [];
        } catch (InvalidPolicyDocumentException) {
            $screen->refuse(new Refusal(RefusalReason::INVALID_POLICY, null, null, null, 'a policy attached to a record cannot be read'));

            return;
        }

        $covers   = static fn (Statement $statement): bool => $statement->coversAction($action);
        $material = \array_filter($policies, static fn (Policy $policy): bool => \array_filter($policy->statements, $covers) !== []);

        foreach ($material as $policy) {
            $screen->refuse(new Refusal(RefusalReason::RECORD_ATTACHMENT, $policy->name . ($policy->id === null ? '' : "[{$policy->id}]")));
        }
    }

    /**
     * Return the condition a row of the class meets when `check()` allows it:
     * none when the pipeline, deciding the class in the scope `check()` decides
     * its rows in, having screened every statement it weighs, does not allow
     * it; else, when a material statement matches a pattern against the
     * identifier, that the row's key is short enough for `fnmatch()`. A class
     * with a refusal, or whose documents cannot be read, keeps no row, and the
     * refusal is kept.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Query\StatementScreen  $screen
     * @return string
     */
    private function decideClass(ResourceShape $shape, Subject $subject, string $action, array $context, ?Reference $tenant, StatementScreen $screen): string
    {
        $resource    = ResourceReference::record($shape->type, '*', $tenant);
        $isPatterned = false;

        $decide = function () use ($subject, $action, $context, $resource, $screen, &$isPatterned): Decision {
            try {
                $sources = $this->pipeline->sources($subject, $action, $resource, $context);
            } catch (InvalidPolicyDocumentException) {
                $screen->refuse(new Refusal(RefusalReason::INVALID_POLICY));

                return Decision::deny(DecisionReason::INVALID_POLICY, DecisionStage::DENY);
            }

            $isPatterned = $screen->screen($sources, $resource->identifier) !== [];

            return $screen->refusals() === [] ? $this->pipeline->weigh($sources, $action, $resource) : Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        };

        return ResourceScope::decide($subject, $action, $resource, $decide)->isAllowed() ? self::shortKey($shape, $isPatterned) : self::NO_ROW;
    }

    /**
     * Return the condition a row's key meets when its identifier is short
     * enough for `fnmatch()`, when a material statement matches a pattern
     * against it; every row's key is, when its kind bounds its length.
     *
     * @param  \SineMacula\Laravel\Authorization\Query\ResourceShape  $shape
     * @param  bool  $isPatterned
     * @return string
     */
    private static function shortKey(ResourceShape $shape, bool $isPatterned): string
    {
        $length = $isPatterned ? $shape->dialect->keyLength($shape->key, $shape->keyKind, $shape->isIntegerCast) : null;

        return $length === null ? self::EVERY_ROW : $length . ' <= ' . (\PHP_MAXPATHLEN - \strlen($shape->type) - 2);
    }

    /**
     * Return the conjunction of the conditions.
     *
     * @param  list<string>  $conditions
     * @return string
     */
    private static function all(array $conditions): string
    {
        $conditions = \array_values(\array_unique(\array_diff($conditions, [self::EVERY_ROW])));

        return \in_array(self::NO_ROW, $conditions, true) ? self::NO_ROW : self::joined($conditions, ' AND ', self::EVERY_ROW);
    }

    /**
     * Return the disjunction of the conditions.
     *
     * @param  list<string>  $conditions
     * @return string
     */
    private static function any(array $conditions): string
    {
        $conditions = \array_values(\array_unique(\array_diff($conditions, [self::NO_ROW])));

        return \in_array(self::EVERY_ROW, $conditions, true) ? self::EVERY_ROW : self::joined($conditions, ' OR ', self::NO_ROW);
    }

    /**
     * Return the conditions joined by the operator, grouped, the one condition
     * alone, or the condition given for none.
     *
     * @param  list<string>  $conditions
     * @param  string  $operator
     * @param  string  $none
     * @return string
     */
    private static function joined(array $conditions, string $operator, string $none): string
    {
        return match (\count($conditions)) {
            0       => $none,
            1       => $conditions[0],
            default => '(' . \implode($operator, $conditions) . ')',
        };
    }
}
