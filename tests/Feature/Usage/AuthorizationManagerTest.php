<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use Tests\Concerns\ReviewsAccess;
use Tests\Concerns\TracksGrantUsage;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Feature tests for what the authorization manager's decisions count as grant
 * use while usage tracking is on (N100): every live route behind an allowed
 * permission, redundant ones included, and every policy whose statement
 * decided, each everyday form of check alike; and every excluded path (a
 * preview, an explanation, `authorization:why`, a listing of permissions, a
 * scoped query and a review's admission) counting none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationManager::class)]
final class AuthorizationManagerTest extends TestCase
{
    use ReviewsAccess, TracksGrantUsage;

    /**
     * An allow by a permission counts every live route behind it, redundant
     * ones included: the direct grant, each role grant that carried it with the
     * ancestor it reached, and the identity's grant; routes behind other
     * permissions count nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAllowCountsEveryRouteBehindItsPermission(): void
    {
        $read     = self::permission('posts:read');
        $admin    = self::role('admin');
        $editor   = self::role('editor', $admin);
        $writer   = self::role('writer');
        $identity = self::identity('person');
        $ann      = StubSecondIdentity::query()->create(['id' => 'ann']);

        $admin->givePermissionTo($read);
        $writer->givePermissionTo($read);
        $writer->givePermissionTo(self::permission('posts:write'));

        self::grants()->grantPermission($ann, $read);
        self::grants()->grantRole($ann, $editor);
        self::grants()->grantRole($ann, $writer);
        self::grants()->grantPermission($identity, $read);

        self::assertTrue($this->actAs($ann, $identity)->check('posts:read')->isAllowed());

        $expected = self::keysHeld($ann, $identity, static fn ($row): bool => \in_array(self::describe($row), [
            'permission_grant ann posts:read',
            'permission_grant ann via person posts:read',
            'role_grant ann [editor] editor',
            'role_inherited ann [editor>admin] admin',
            'role_permission ann [editor>admin] posts:read',
            'role_grant ann [writer] writer',
            'role_permission ann [writer] posts:read',
        ], true));

        self::assertCount(7, $expected);
        self::assertSame($expected, $this->keysObserved());
    }

    /**
     * A policy counts whenever one of its statements decided: a deny-only
     * policy that denies, and an allowing one that allows; a policy whose
     * statements decided nothing counts nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyCountsWhenOneOfItsStatementsDecided(): void
    {
        $ann     = self::identity('ann');
        $role    = self::role('author');
        $denying = self::policy('no-delete');
        $idle    = self::policy('no-delete-twice');

        self::grants()->attachPolicy($ann, $denying);
        self::grants()->attachPolicy($role, self::policy('may-delete', true));
        self::grants()->grantRole($ann, $role);
        self::grants()->attachPolicy(self::identity('bob'), $idle);

        self::assertFalse($this->actAs($ann)->check('posts:delete')->isAllowed());

        $keys = self::keysHeld($ann, null, self::targeting('no-delete'));

        self::assertSame($keys, $this->keysObserved());

        self::grants()->detachPolicy($ann, $denying);

        self::assertTrue($this->actAs($ann)->check('posts:delete')->isAllowed());
        self::assertSame(self::keysHeld($ann, null, self::targeting('may-delete', 'author')), $this->keysObserved());
    }

    /**
     * Every everyday form of check counts: `can()`, `cannot()`, `any()`,
     * `all()`, `authorize()`, `checkMany()`, `canEach()`, the Gate, Blade and
     * the middleware.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryEverydayFormOfCheckCounts(): void
    {
        $forms = [
            'can'       => static fn (AuthorizationManager $manager): mixed => $manager->can('posts:read'),
            'cannot'    => static fn (AuthorizationManager $manager): mixed => $manager->cannot('posts:read'),
            'any'       => static fn (AuthorizationManager $manager): mixed => $manager->any(['posts:read', 'posts:none']),
            'all'       => static fn (AuthorizationManager $manager): mixed => $manager->all(['posts:read']),
            'authorize' => static function (AuthorizationManager $manager): void {
                $manager->authorize('posts:read');
            },
            'checkMany'  => static fn (AuthorizationManager $manager): mixed => $manager->checkMany([new CheckInput('posts:read'), new CheckInput('posts:read', 'posts/1')]),
            'canEach'    => static fn (AuthorizationManager $manager): mixed => $manager->canEach('posts:read', ['posts/1', 'posts/2']),
            'gate'       => static fn (AuthorizationManager $manager): mixed => Gate::forUser($manager->currentSubject()?->subject)->allows(PackagePermissions::REVIEW_READ),
            'blade'      => static fn (): string => Blade::render('@permission(\'posts:read\') yes @endpermission'),
            'middleware' => static function (): void {
                $middleware = app(RequirePermission::class);

                $middleware->handle(Request::create('/posts'), static fn (): Response => new Response('ok'), 'posts:read');
            },
        ];

        $read   = self::permission('posts:read');
        $review = self::permission(PackagePermissions::REVIEW_READ);

        foreach ($forms as $form => $check) {
            $user = self::identity('user-' . $form);

            self::grants()->grantPermission($user, $form === 'gate' ? $review : $read);

            $check($this->actAs($user));

            self::assertSame(self::keysHeld($user), $this->keysObserved(), "{$form}() counted no use.");
        }
    }

    /**
     * No path that is not an everyday decision counts: a preview, an
     * explanation, `authorization:why`, a listing of permissions, a scoped
     * query, a review's admission and a review's read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoIntrospectionCounts(): void
    {
        $ann     = self::identity('ann');
        $caller  = self::identity('caller');
        $read    = self::permission('posts:read');
        $preview = self::permission(PackagePermissions::SUBJECT_PREVIEW);

        self::grants()->grantPermission($ann, $read);
        self::grants()->grantPermission($caller, $preview);
        self::grants()->grantPermission($caller, self::permission(PackagePermissions::REVIEW_READ));
        self::keyCursors();

        $manager = $this->actAs($caller);

        self::assertTrue($manager->previewFor($ann)->check('posts:read')->isAllowed());
        self::assertNull($this->actAs($ann)->explain('posts:read')->reason);
        $this->actAs($ann)->permissionsFor(null, AuthorizationScope::platform());

        $this->actAs($ann)->queryScope(new ScopedPost, 'posts:read');

        Artisan::call('authorization:why', ['subject' => $ann->getMorphClass() . ':ann', 'action' => 'posts:read']);

        $this->actAs($caller);

        app(AccessReview::class)->review(ReviewQuery::holdings($ann, ReviewScope::everywhere()), ActingContext::current());

        self::assertSame([], $this->keysObserved());
        self::assertSame(0, $this->recorder()->pending());
    }

    /**
     * A refused administration stage keeps the allow it refused from counting;
     * a refusal it never reached counts as any denial does: nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedReviewAdmissionCountsNothing(): void
    {
        $reviewer = self::identity('reviewer');

        $this->actAs($reviewer);

        try {
            app(AccessReview::class)->review(ReviewQuery::holdings($reviewer, ReviewScope::everywhere()), ActingContext::current());
            self::fail('A reviewer without the right was admitted.');
        } catch (AuthorizationException) {
            self::assertSame([], $this->keysObserved());
        }
    }

    /**
     * A warm check counts its routes from what the cache keeps, with no query,
     * every time the bucket is new to the worker.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWarmCheckCountsWithNoQuery(): void
    {
        $ann = self::identity('ann');

        self::grants()->grantPermission($ann, self::permission('posts:read'));

        config(['authorization.usage.interval' => 60]);
        Carbon::setTestNow('2026-11-09 10:00:00');

        $manager = $this->actAs($ann);

        self::assertTrue($manager->check('posts:read')->isAllowed());
        self::assertSame(self::keysHeld($ann), $this->keysObserved());

        Carbon::setTestNow('2026-11-09 10:01:30');

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        self::assertTrue($manager->check('posts:read')->isAllowed());
        self::assertSame(0, $queries);
        self::assertSame(self::keysHeld($ann), $this->keysObserved());
    }

    /**
     * A check denied before its grants are weighed, and a denial by no
     * statement, count nothing; so does a `withPolicies()` override's
     * statement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADenialOrAnOverrideCountsNoGrant(): void
    {
        $ann = self::identity('ann');

        self::grants()->attachPolicy($ann, self::policy('no-delete'));

        self::assertFalse($this->actAs($ann)->check('posts:read')->isAllowed());

        $override = EvaluationPolicy::fromArray(['name' => 'override', 'statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]]]);

        self::assertFalse($this->actAs($ann)->withPolicies([$override])->check('posts:delete')->isAllowed());
        self::assertFalse(Authorization::forUser(null)->check('posts:delete')->isAllowed());
        self::assertSame([], $this->keysObserved());
    }
}
