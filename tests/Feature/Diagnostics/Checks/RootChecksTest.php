<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Diagnostics\Checks\RootChecks;
use SineMacula\Laravel\Authorization\Diagnostics\ConfigIssue;
use SineMacula\Laravel\Authorization\Diagnostics\IssueCollector;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use Tests\Feature\Stubs\StubPolicyStore;
use Tests\Fixtures\GrantHooks\RecordingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for the structural checks of the settings at the top of the
 * configuration, each setting and each entry on its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RootChecks::class)]
final class RootChecksTest extends TestCase
{
    /**
     * Every entry is checked on its own, so each refused entry is listed, and a
     * name two tables share is refused only among the names that passed, once
     * every name is checked.
     *
     * @return void
     */
    public function testEachEntryIsCheckedOnItsOwn(): void
    {
        self::assertSame([
            ['authorization.tables.guardrails', 'out_of_range'],
            ['authorization.tables.permissions', 'duplicate'],
            ['authorization.permission_enums.0', 'invalid_type'],
            ['authorization.permission_enums.1', 'unknown_class'],
            ['authorization.application_access', 'invalid_value'],
            ['authorization.application_access', 'invalid_value'],
        ], $this->issues([
            'tables'             => ['roles' => 'Shared', 'permissions' => 'shared', 'guardrails' => \str_repeat('g', 64)],
            'permission_enums'   => [3, 'Missing\Enum'],
            'application_access' => ['portal' => '', 'admin' => 'admin.access', '' => 'x'],
        ]));
    }

    /**
     * Each seam is checked on its own, a null policy store meaning none, and a
     * refused block skips each setting it holds.
     *
     * @return void
     */
    public function testSeamsAndBlocksAreCheckedOnTheirOwn(): void
    {
        self::assertSame([
            ['authorization.defaults', 'invalid_type'],
            ['authorization.defaults.guard', 'skipped'],
            ['authorization.models', 'invalid_type'],
            ['authorization.models.role', 'skipped'],
            ['authorization.models.permission', 'skipped'],
            ['authorization.models.policy', 'skipped'],
            ['authorization.subject_resolver', 'required'],
            ['authorization.tenant_tree', 'not_implemented'],
            ['authorization.requirement_checker', 'invalid_type'],
        ], $this->issues([
            'defaults'            => 'web',
            'models'              => null,
            'subject_resolver'    => null,
            'tenant_tree'         => StubPolicyStore::class,
            'requirement_checker' => 3,
            'policy_store'        => null,
        ]));

        self::assertSame([['authorization.policy_store', 'not_implemented']], $this->issues(['policy_store' => FlatTenantTree::class]));
    }

    /**
     * A grant hooks value that is not a list is refused once; a hook listed
     * twice, whatever its case, is refused as a duplicate.
     *
     * @return void
     */
    public function testTheGrantHooksAreCheckedEachOnItsOwn(): void
    {
        self::assertSame([['authorization.grant_hooks', 'invalid_type']], $this->issues(['grant_hooks' => ['a' => RecordingGrantHook::class]]));
        self::assertSame(
            [['authorization.grant_hooks.1', 'duplicate'], ['authorization.grant_hooks.2', 'unknown_class']],
            $this->issues(['grant_hooks' => [RecordingGrantHook::class, '\\' . \strtoupper(RecordingGrantHook::class), 'Missing\Hook']]),
        );
    }

    /**
     * Return the path and code of each issue the checks find in the suite's
     * configuration with the settings given.
     *
     * @param  array<string, mixed>  $settings
     * @return list<array{string, string}>
     */
    private function issues(array $settings): array
    {
        $collector = new IssueCollector;

        (new RootChecks($collector, $this->container(), [...$this->authorizationConfig(), ...$settings]))->run();

        return \array_map(static fn (ConfigIssue $issue): array => [$issue->path, $issue->code->value], $collector->findings()->issues);
    }
}
