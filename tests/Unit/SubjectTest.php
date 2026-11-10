<?php

declare(strict_types = 1);

namespace Tests\Unit;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Unit tests for `Subject`, who a decision is about and where it is made.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Subject::class)]
final class SubjectTest extends TestCase
{
    /**
     * A subject named alone has no identity, tenant, application, guard or
     * session.
     *
     * @return void
     */
    public function testOnlyTheSubjectIsRequired(): void
    {
        $model   = new \stdClass;
        $subject = new Subject($model);

        self::assertSame($model, $subject->subject);
        self::assertNull($subject->identity);
        self::assertNull($subject->tenant);
        self::assertNull($subject->application);
        self::assertNull($subject->guard);
        self::assertNull($subject->session);
        self::assertNull($subject->scopes);
        self::assertFalse($subject->platform);
    }

    /**
     * Every part given is kept.
     *
     * @return void
     */
    public function testKeepsEveryPart(): void
    {
        $model    = new \stdClass;
        $identity = new \stdClass;
        $tenant   = new \stdClass;
        $subject  = new Subject($model, $identity, $tenant, 'admin', 'web', 'session-1');

        self::assertSame($model, $subject->subject);
        self::assertSame($identity, $subject->identity);
        self::assertSame($tenant, $subject->tenant);
        self::assertSame('admin', $subject->application);
        self::assertSame('web', $subject->guard);
        self::assertSame('session-1', $subject->session);
        self::assertNull($subject->scopes);
        self::assertFalse($subject->platform);
    }

    /**
     * A subject on the platform keeps its marker and its credential's scopes,
     * an empty list kept apart from null.
     *
     * @return void
     */
    public function testKeepsTheScopesAndThePlatformMarker(): void
    {
        $model = new \stdClass;

        self::assertSame(['posts:read', 'posts:*'], (new Subject($model, scopes: ['posts:read', 'posts:*']))->scopes);
        self::assertSame([], (new Subject($model, scopes: []))->scopes);
        self::assertNull((new Subject($model, scopes: null))->scopes);
        self::assertTrue((new Subject($model, null, null, 'admin', platform: true))->platform);
        self::assertSame('admin', (new Subject($model, null, null, 'admin', platform: true))->application);
    }

    /**
     * A subject on the platform that names a tenant is refused, since it cannot
     * be both.
     *
     * @return void
     */
    public function testASubjectOnThePlatformInATenantIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A subject on the platform names no tenant.');

        new Subject(new \stdClass, null, new \stdClass, platform: true);
    }

    /**
     * Scopes that are not a list of strings that are not empty are refused: a
     * map, a list with an entry that is not a string, and one with an empty
     * string.
     *
     * @return void
     */
    public function testScopesThatAreNotAListOfNamesAreRefused(): void
    {
        $invalid = [
            'a map'         => [1 => 'posts:read'],
            'a keyed map'   => ['read' => 'posts:read'],
            'a number'      => ['posts:read', 42],
            'an empty name' => ['posts:read', ''],
            'a null entry'  => [null],
        ];

        foreach ($invalid as $case => $scopes) {
            try {
                new Subject(new \stdClass, scopes: $scopes); // @phpstan-ignore argument.type (each is refused at run time)

                self::fail('The scopes are refused: ' . $case . '.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('The scopes of a subject must be a list of strings that are not empty, or null for no cap.', $exception->getMessage(), $case);
            }
        }
    }

    /**
     * Another model keeps the platform marker, so the same request stays on the
     * platform, and loses the credential's scopes with the session.
     *
     * @return void
     */
    public function testWithSubjectKeepsTheMarkerAndDropsTheScopes(): void
    {
        $model   = new \stdClass;
        $request = new Subject($model, $model, null, 'admin', 'web', 'session-1', ['posts:read'], true);
        $other   = $request->withSubject(new \stdClass);
        $same    = $request->withSubject($model);

        self::assertTrue($other->platform);
        self::assertNull($other->scopes);
        self::assertNull($other->session);
        self::assertTrue($same->platform);
        self::assertNull($same->scopes);
        self::assertNull($same->session);
        self::assertSame('admin', $same->application);
    }

    /**
     * A subject with no session deciding about another model loses its scopes
     * too, and one deciding about its own model is returned as it is, its
     * scopes and marker included.
     *
     * @return void
     */
    public function testWithSubjectKeepsTheScopesOnlyWhenItReturnsItself(): void
    {
        $model   = new \stdClass;
        $request = new Subject($model, $model, scopes: [], platform: true);
        $other   = $request->withSubject(new \stdClass);

        self::assertSame($request, $request->withSubject($model));
        self::assertSame([], $request->withSubject($model)->scopes);
        self::assertNull($other->scopes);
        self::assertTrue($other->platform);
        self::assertFalse((new Subject($model, $model, new \stdClass))->withSubject(new \stdClass)->platform);
    }

    /**
     * Another model keeps the tenant, application and guard, and is its own
     * identity.
     *
     * @return void
     */
    public function testWithSubjectKeepsTheRequestForAnotherModel(): void
    {
        $tenant  = new \stdClass;
        $request = new Subject(new \stdClass, new \stdClass, $tenant, 'admin', 'web');
        $other   = new \stdClass;
        $subject = $request->withSubject($other);

        self::assertNotSame($request, $subject);
        self::assertSame($other, $subject->subject);
        self::assertSame($other, $subject->identity);
        self::assertSame($tenant, $subject->tenant);
        self::assertSame('admin', $subject->application);
        self::assertSame('web', $subject->guard);
    }

    /**
     * The model the subject is already about keeps the subject unchanged, its
     * identity included.
     *
     * @return void
     */
    public function testWithTheSameModelKeepsTheSubject(): void
    {
        $model   = new \stdClass;
        $request = new Subject($model, new \stdClass, new \stdClass, 'admin', 'web');

        self::assertSame($request, $request->withSubject($model));
    }

    /**
     * An equal but distinct model is another model.
     *
     * @return void
     */
    public function testWithAnEqualModelIsAnotherSubject(): void
    {
        $identity = new \stdClass;
        $request  = new Subject(new \stdClass, $identity);
        $other    = new \stdClass;

        self::assertNotSame($identity, $request->withSubject($other)->identity);
        self::assertSame($other, $request->withSubject($other)->identity);
    }

    /**
     * Another model never keeps the session, so a subject the caller names
     * meets no authentication requirement.
     *
     * @return void
     */
    public function testWithSubjectDropsTheSession(): void
    {
        $request = new Subject(new \stdClass, new \stdClass, null, 'admin', 'web', 'session-1');

        self::assertNull($request->withSubject(new \stdClass)->session);
    }

    /**
     * Naming the model a subject in a session is about gives the same subject,
     * its identity included, without the session.
     *
     * @return void
     */
    public function testWithTheSameModelDropsTheSession(): void
    {
        $model    = new \stdClass;
        $identity = new \stdClass;
        $tenant   = new \stdClass;
        $request  = new Subject($model, $identity, $tenant, 'admin', 'web', 'session-1');
        $subject  = $request->withSubject($model);

        self::assertNotSame($request, $subject);
        self::assertSame($model, $subject->subject);
        self::assertSame($identity, $subject->identity);
        self::assertSame($tenant, $subject->tenant);
        self::assertSame('admin', $subject->application);
        self::assertSame('web', $subject->guard);
        self::assertNull($subject->session);
    }
}
