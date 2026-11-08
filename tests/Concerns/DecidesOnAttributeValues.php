<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\RecordingSubjectAttributes;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\BulkChecks\StatusAttributes;
use Tests\Fixtures\QueryScoping\ScopedPost;

/**
 * Makes decisions whose conditions read a resource attribute, a subject
 * attribute and a value the caller passes, each a value no decision event may
 * carry (AUTHZ-15.4), and asserts an event carries none of them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait DecidesOnAttributeValues
{
    /** @var string The action the policy allows. */
    protected const string VALUE_ACTION = 'posts:read';

    /** @var string The status a post the policy allows has. */
    protected const string SECRET_STATUS = 'status-kept-secret';

    /** @var string The status of a post the policy does not allow. */
    protected const string SECRET_DRAFT = 'draft-kept-secret';

    /** @var string The value the caller passes for the policy to test. */
    protected const string SECRET_INPUT = 'input-kept-secret';

    /** @var string The name of the subject, which no event names. */
    protected const string SECRET_NAME = 'name-kept-secret';

    /**
     * Make the request's subject, in a tenant and an application, with the
     * posts' status and the subject's department readable as attributes, and
     * return it.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    protected function valueReadingSubject(): StubIdentity
    {
        $user   = StubIdentity::create(['id' => 'user-1', 'name' => self::SECRET_NAME]);
        $tenant = StubTenant::query()->create(['id' => 'tenant-1', 'name' => 'tenant-1']);

        config([
            'authorization.attributes.resources' => [(new ScopedPost)->getMorphClass() => StatusAttributes::class],
            'authorization.attributes.subjects'  => [$user->getMorphClass() => RecordingSubjectAttributes::class],
        ]);

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $tenant, 'admin'));
        $this->app?->forgetInstance(CheckContextFactory::class);
        $this->app?->forgetInstance(AuthorizationManager::class);
        $this->app?->forgetInstance('authorization');

        Authorization::clearResolvedInstance('authorization');

        return $user;
    }

    /**
     * Create a tenant below the request's tenant, `tenant-1`, in the tenant
     * tree, and return it.
     *
     * @return \Tests\Feature\Stubs\StubTenant
     */
    protected function childTenant(): StubTenant
    {
        $child = StubTenant::query()->create(['id' => 'tenant-2', 'name' => 'tenant-2']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), new Reference($child->getMorphClass(), 'tenant-1')));

        return $child;
    }

    /**
     * Return a post with the status given.
     *
     * @param  string  $status
     * @return \Tests\Fixtures\QueryScoping\ScopedPost
     */
    protected static function postWithStatus(string $status): ScopedPost
    {
        return ScopedPost::query()->create(['title' => 'post', 'status' => $status]);
    }

    /**
     * Return a policy allowing the action on a post whose status, subject's
     * department and caller-supplied reason hold the values it tests.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    protected static function valueReadingPolicy(): Policy
    {
        return Policy::fromArray(['name' => 'audited', 'statements' => [[
            'sid'        => 'read-audited',
            'effect'     => 'allow',
            'actions'    => [self::VALUE_ACTION],
            'conditions' => ['eq' => ['resource.status' => self::SECRET_STATUS, 'subject.department' => 'sales', 'input.reason' => self::SECRET_INPUT]],
        ]]]);
    }

    /**
     * Assert the event, serialised as a queued listener would serialise it or
     * encoded as JSON, carries none of the values the decision read, nor the
     * subject's name.
     *
     * @param  object  $event
     * @return void
     */
    protected static function assertCarriesNoValue(object $event): void
    {
        foreach ([\serialize($event), (string) \json_encode($event)] as $payload) {
            foreach ([self::SECRET_STATUS, self::SECRET_INPUT, self::SECRET_NAME, self::SECRET_DRAFT, 'sales', '90000'] as $value) {
                self::assertStringNotContainsString($value, $payload);
            }
        }
    }
}
