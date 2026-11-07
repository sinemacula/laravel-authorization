<?php

declare(strict_types = 1);

namespace Tests\Unit\Query;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Query\ClassRequest;
use SineMacula\Laravel\Authorization\Query\ResourceShape;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Query\StatementScreen;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Unit tests for what every class of one query's rows is decided for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClassRequest::class)]
final class ClassRequestTest extends TestCase
{
    /**
     * The request holds what it is given, with no attachments by default.
     *
     * @return void
     */
    public function testTheRequestHoldsWhatItIsGiven(): void
    {
        $user    = StubIdentity::create(['id' => 'u1']);
        $subject = new Subject($user, $user);
        $shape   = ResourceShape::of(new ScopedPost, 'posts:view', new SchemaInspector);
        $screen  = new StatementScreen('posts:view', $shape, $subject);
        $request = new ClassRequest($shape, $subject, 'posts:view', ['flag' => 'on'], $screen);

        $held = [$request->shape, $request->subject, $request->action, $request->context, $request->screen, $request->attachments];

        self::assertSame([$shape, $subject, 'posts:view', ['flag' => 'on'], $screen, null], $held);
    }
}
