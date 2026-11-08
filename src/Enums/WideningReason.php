<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

/**
 * Why a proposed grant widens an identity's scope, as the grant hook is told it
 * (AUTHZ-11.3).
 *
 * The first four are proven widenings. The next two are doubts: the package
 * could not prove the grant stays within what the identity already held, and
 * calls the hook rather than skip it. The last is for an application calling
 * the hook on its own membership path (AUTHZ-13.9).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum WideningReason: string
{
    /** The grantee is the identity itself, so the grant holds across every principal of it. */
    case IDENTITY = 'identity';

    /** The grant is platform-wide. */
    case PLATFORM = 'platform';

    /** No live grant of the identity or of any of its principals applied in the grant's tenant before. */
    case NEW_TENANT = 'new_tenant';

    /** The grant reaches below its tenant, where no live grant of the identity or of its principals reached below before. */
    case NEW_SUBTREE = 'new_subtree';

    /** The identity directory's list of the identity's principals is incomplete, so a grant already held could not be proven. */
    case INCOMPLETE_DIRECTORY = 'incomplete_directory';

    /** The tenant tree could not be read, so a grant already held could not be proven. */
    case UNREADABLE_TREE = 'unreadable_tree';

    /** A membership the application creates or accepts on its own path. */
    case MEMBERSHIP = 'membership';
}
