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
