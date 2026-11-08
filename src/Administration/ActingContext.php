<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Container\Container;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Preview\Previewing;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Who is making a delegated administration call (AUTHZ-11.1): the resolved
 * acting subject (its principal, the identity behind it, its guard, its session
 * and, for a machine, the scopes of its credential, which cap every check as
 * they cap the request's), any caps the call adds, and who is impersonating it,
 * when someone is.
 *
 * A management service given an acting context decides each change it makes
 * through `check()`, as this subject, on the change's operation resource, and
 * refuses with the decision when it is not allowed. A service given none runs
 * as trusted system work (N75). An acting context is built from a resolved
 * subject only, never from a bare reference: `current()` takes the request's
 * subject as `check()` resolves it, its session kept, so a step-up met in the
 * session counts; `for()` names another, as `Authorization::for()` names one,
 * with no session, so an authentication requirement is never met for it, unless
 * it is handed a resolved `Subject`, which is kept as it is. A subject that
 * cannot be resolved, or whose principal is not a saved model, refuses with
 * `AuthorizationException`, as `subject_unresolved`, and never falls back to a
 * trusted call.
 *
 * A preview confers no authority (AUTHZ-11.4, N87): an acting context built
 * while a preview is evaluated, by a callback or a listener it runs, or built
 * from a preview's target, the subject a preview manager's `currentSubject()`
 * returns, is refused as `administration.previewing`, with no override (see
 * `Preview\Previewing`).
 *
 * The package never impersonates, so the application says when the acting
 * subject is impersonated, with `impersonatedBy()`. Every delegated change made
 * while impersonating is refused as `administration.impersonating` unless a
 * policy allows `authorization:administration.impersonated` for the acting
 * subject on the same operation; both actors are reported with the change.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ActingContext
{
    /**
     * Create a new acting context.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  list<list<string>>  $caps
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $impersonator
     */
    private function __construct(

        /** The acting subject, as `check()` decides about it. */
        public Subject $subject,

        /** The caps the call adds, each a list of actions or action patterns, every one of which must cover a decided action. */
        public array $caps = [],

        /** Who is impersonating the acting subject, or null when no one is. */
        public ?Reference $impersonator = null,
    ) {}

    /**
     * Return the acting context of the current request or job: its subject as
     * `check()` resolves it, its session kept.
     *
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public static function current(): self
    {
        return self::resolved(AuthorizationManager::instance()?->currentSubject());
    }

    /**
     * Return the acting context of the actor: a resolved `Subject` as it is,
     * else the model named as `Authorization::for()` names it, in the request's
     * tenant, application and guard, with no session.
     *
     * @param  object  $actor
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public static function for(object $actor): self
    {
        return self::resolved($actor instanceof Subject ? $actor : AuthorizationManager::instance()?->for($actor)->currentSubject());
    }

    /**
     * Return this acting context with the call capped by the actions as well,
     * each an action or an action pattern, as `Authorization::capped()` caps a
     * check: an administration action none of them covers is refused.
     *
     * @param  list<string>  $actions
     * @return self
     */
    public function capped(array $actions): self
    {
        return new self($this->subject, [...$this->caps, $actions], $this->impersonator);
    }

    /**
     * Return this acting context impersonated by the given model or reference,
     * the authenticated actor behind the acting subject.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $impersonator
     * @return self
     */
    public function impersonatedBy(Model|Reference $impersonator): self
    {
        return new self($this->subject, $this->caps, Reference::of($impersonator));
    }

    /**
     * Determine whether someone is impersonating the acting subject.
     *
     * @return bool
     */
    public function isImpersonating(): bool
    {
        return $this->impersonator !== null;
    }

    /**
     * Return the reference to the acting subject's principal.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    public function principal(): Reference
    {
        /** @var \Illuminate\Database\Eloquent\Model $principal */
        $principal = $this->subject->subject;

        return Reference::of($principal);
    }

    /**
     * Return the reference to the identity behind the acting principal, or null
     * when it has none that is a saved model.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function identity(): ?Reference
    {
        $identity = $this->subject->identity;

        return $identity instanceof Model && $identity->exists ? Reference::of($identity) : null;
    }

    /**
     * Decide the operation's action on the operation resource as the acting
     * subject, through `check()`, so a screen asks exactly what the service
     * asks and gets the same decision. The decision is recorded and reported as
     * `check()` records it.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function check(OperationResource $operation): Decision
    {
        $resource = $operation->actedBy($this->impersonator);

        return $this->decide($resource->action, $resource);
    }

    /**
     * Decide any action as the acting subject, with the call's caps, through
     * `check()`, as the guardrail service decides its own right. The decision
     * is recorded and reported as `check()` records it.
     *
     * @param  string  $action
     * @param  mixed  $resource
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function decide(string $action, mixed $resource = null): Decision
    {
        return $this->manager()->check($action, $resource);
    }

    /**
     * Decide the operation as `check()` does and throw when it is not allowed:
     * an `InsufficientAuthenticationException` for a step-up, else an
     * `AuthorizationException`, each carrying the decision, after the refusal
     * is reported with `AuthorizationFailed`, as `authorize()` reports one.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function authorize(OperationResource $operation): void
    {
        $resource = $operation->actedBy($this->impersonator);

        $this->manager()->authorize($resource->action, $resource);
    }

    /**
     * Decide every change the operation makes through `authorize()`, each
     * correlated with the operation by its id, and throw at the first that is
     * not allowed. A service decides them all before it writes any, inside the
     * operation's transaction, so a refusal leaves nothing written and no
     * change decides another on authority an earlier one would have handed out.
     * The changes are decided kind by kind, in the order their actions first
     * appear, and within a kind by their tenant, application and record, so the
     * first refusal of a batch never depends on the order its rows were read
     * in.
     *
     * Inside a delegated operation's work, the concurrency protocol runs around
     * the decisions (see `DependencyPins`): the actor's authority and what the
     * changes change are locked and pinned before the first is decided, the
     * holders a change reaches as they are read, and once every change is
     * allowed, all of it is read again and the operation is tried again when
     * anything changed.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  ...$changes
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     * @throws \LogicException
     */
    public function authorizeIn(Operation $operation, OperationResource ...$changes): void
    {
        $changes = self::ordered($changes);
        $pins    = OperationScope::pins();

        $pins?->lockChanges(...$changes);

        foreach ($changes as $change) {
            $this->authorize($change->actedBy($this->impersonator, $operation->id));
        }

        $pins?->validate();
    }

    /**
     * Decide every change the operation makes, as `authorizeIn()` does, or,
     * when it makes none, the changes it was asked for that change nothing, so
     * a call that finds nothing to change is still decided on its actions: an
     * actor that may not take them is refused whether or not there was anything
     * to change, and cannot learn what a grantee holds by asking.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  list<\SineMacula\Laravel\Authorization\Administration\OperationResource>  $changes
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  ...$unchanged
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function authorizeChanges(Operation $operation, array $changes, OperationResource ...$unchanged): void
    {
        $this->authorizeIn($operation, ...($changes === [] ? $unchanged : $changes));
    }

    /**
     * Record and report the decision that refuses the operation as a whole, as
     * the acting subject's, with the call's caps, on the operation resource
     * `authorization:operation:{id}` and the operation's first action, as
     * `authorize()` records and reports a refusal, and return the
     * `AuthorizationException` that carries it: what refuses an operation that
     * conflicted on every try (see `ConflictRetries`).
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Operation  $operation
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function reportRefusal(Operation $operation, Decision $decision): AuthorizationException
    {
        $resource = new ResourceReference(OperationResource::TYPE . ':' . $operation->id, OperationResource::TYPE, $operation->id);

        return $this->manager()->reportRefusal($operation->actions[0] ?? OperationResource::TYPE, $resource, $decision);
    }

    /**
     * Return the refusal the decision makes: an `AuthorizationException` with
     * its reason and the one `denied` line the bound translator words, carrying
     * the decision.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public static function refusal(Decision $decision): AuthorizationException
    {
        $container  = Container::getInstance();
        $translator = $container->bound('translator') ? $container->make('translator') : null;

        return AuthorizationException::translated($decision->reason ?? DecisionReason::NO_MATCH, $translator instanceof Translator ? $translator : null, $decision);
    }

    /**
     * Return the changes in the order a batch decides them: kind by kind, in
     * the order their actions first appear, and within a kind by where each
     * holds and what it acts on.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Administration\OperationResource>  $changes
     * @return list<\SineMacula\Laravel\Authorization\Administration\OperationResource>
     */
    private static function ordered(array $changes): array
    {
        $kinds = \array_flip(\array_unique(\array_map(static fn (OperationResource $change): string => $change->action, $changes)));

        $order = static fn (OperationResource $change): array => [$kinds[$change->action], self::placeOf($change)];

        \usort($changes, static fn (OperationResource $one, OperationResource $other): int => $order($one) <=> $order($other));

        return $changes;
    }

    /**
     * Return where the change holds and what it acts on, as one string: its
     * tenant, its application and its record's type and key.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $change
     * @return string
     */
    private static function placeOf(OperationResource $change): string
    {
        $target = $change->change?->target;

        return \serialize([$change->tenant, $change->change?->scope->application, $target?->getMorphClass(), $target?->getKey()]);
    }

    /**
     * Return the acting context of the resolved subject, refusing none, and a
     * subject whose principal is not a saved model with a key, and, as
     * `administration.previewing`, any while a preview is evaluated and a
     * preview's target.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function resolved(?Subject $subject): self
    {
        Previewing::refuseAuthority($subject);

        $principal = $subject?->subject;

        if (!$principal instanceof Model || !$principal->exists || !\is_scalar($principal->getKey()) || $principal->getKey() === '') {
            throw self::unresolved();
        }

        /** @var \SineMacula\Laravel\Authorization\Subject $subject */
        return new self($subject);
    }

    /**
     * Return the manager deciding about the acting subject, with the call's
     * caps, refusing when the package is not booted.
     *
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private function manager(): AuthorizationManager
    {
        $manager = AuthorizationManager::instance()?->for($this->subject) ?? throw self::unresolved();

        foreach ($this->caps as $cap) {
            $manager = $manager->capped($cap);
        }

        return $manager;
    }

    /**
     * Return the refusal of an acting subject that cannot be resolved.
     *
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function unresolved(): AuthorizationException
    {
        return self::refusal(Decision::deny(DecisionReason::SUBJECT_UNRESOLVED, DecisionStage::SUBJECT));
    }
}
