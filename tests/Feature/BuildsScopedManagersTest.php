<?php

declare(strict_types = 1);

namespace Tests\Feature;

use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\BuildsScopedManagers;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\TestCase;

/**
 * Feature tests for the scoped clones of the authorization manager: each
 * returns a new manager, leaving the one it is called on unchanged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(BuildsScopedManagers::class)]
final class BuildsScopedManagersTest extends TestCase
{
    /**
     * `for()` names the subject, keeping the request's tenant and application,
     * and `forUser()` names the subject the resolver makes of the user, or no
     * subject for a guest; the manager they are called on still decides about
     * the request's subject.
     *
     * @return void
     */
    public function testForAndForUserNameTheSubject(): void
    {
        $user  = StubIdentity::create(['id' => 'scoped-1']);
        $other = StubIdentity::create(['id' => 'scoped-2']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($other, null, 'admin'));

        $manager = Authorization::getFacadeRoot();
        $named   = Authorization::for($user);

        self::assertNotSame($manager, $named);
        self::assertSame($user, $named->currentSubject()?->subject);
        self::assertSame('admin', $named->currentSubject()->application);
        self::assertTrue($named->can('posts:read'));
        self::assertSame($user, Authorization::forUser($user)->currentSubject()?->subject);
        self::assertNull(Authorization::forUser(null)->currentSubject());
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, Authorization::forUser(null)->check('posts:read')->reason);
        self::assertSame($other, Authorization::currentSubject()?->subject);
        self::assertFalse(Authorization::can('posts:read'));

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver);

        self::assertSame($user, Authorization::for($user)->currentSubject()?->identity);

        $subject = new Subject($user, $other, null, 'admin', 'web', 'session-1');

        self::assertSame($subject, Authorization::for($subject)->currentSubject());
        self::assertTrue(Authorization::for($subject)->can('posts:read'));
    }

    /**
     * `withPolicies()` decides through the policies given, and `capped()` caps
     * every check, each in a new manager, the one they are called on unchanged.
     *
     * @return void
     */
    public function testWithPoliciesAndCappedChangeOnlyTheClone(): void
    {
        $user = StubIdentity::create(['id' => 'scoped-3']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        $manager  = Authorization::for($user);
        $override = $manager->withPolicies([EvaluationPolicy::fromArray(['name' => 'edit', 'statements' => [['effect' => 'allow', 'actions' => ['posts:edit']]]])]);
        $capped   = $manager->capped(['posts:edit']);

        self::assertTrue($override->can('posts:edit'));
        self::assertFalse($manager->can('posts:edit'));
        self::assertSame(DecisionReason::SESSION_POLICY, $capped->check('posts:read')->reason);
        self::assertTrue($manager->can('posts:read'));
        self::assertSame(DecisionReason::SESSION_POLICY, $capped->capped(['posts:read'])->check('posts:edit')->reason);
    }

    /**
     * `withoutSessionCaps()` decides every check of a new manager without the
     * credential's scopes, the one it is called on still capped by them, and
     * keeps the explicit caps.
     *
     * @return void
     */
    public function testWithoutSessionCapsChangesOnlyTheClone(): void
    {
        $machine = StubMachine::create(['id' => 'scoped-4']);

        $machine->givePermission(Permission::create(['name' => 'posts:read']));

        $manager = Authorization::for($machine);
        $without = $manager->withoutSessionCaps();

        self::assertNotSame($manager, $without);
        self::assertTrue($without->can('posts:read'));
        self::assertSame(DecisionReason::SESSION_POLICY, $manager->check('posts:read')->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, $without->capped(['posts:edit'])->check('posts:read')->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, $manager->capped(['posts:read'])->check('posts:read')->reason);
    }
}
