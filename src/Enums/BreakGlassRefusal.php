<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

/**
 * Why a break-glass activation, or a surrender, was refused (AUTHZ-11.7), as
 * `BreakGlassRefusedException::getReason()` reports it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum BreakGlassRefusal: string
{
    /** Break-glass is disabled. */
    case DISABLED = 'disabled';

    /** The grantee is a machine, or a model read as another subject's identity. */
    case NOT_HUMAN = 'not_human';

    /** The role is not listed under `break_glass.roles`. */
    case NOT_LISTED = 'not_listed';

    /** The duration is below one minute or above the role's maximum. */
    case DURATION = 'duration';

    /** The justification is not one of the configured codes. */
    case JUSTIFICATION = 'justification';

    /** A note was given while `notes` is false. */
    case NOTE_REFUSED = 'note_refused';

    /** The note is longer than `note_max_length`. */
    case NOTE_TOO_LONG = 'note_too_long';

    /** The scope names half a tenant. */
    case HALF_TENANT = 'half_tenant';

    /** Someone other than the activation's grantee, or someone impersonating it, tried to surrender it. */
    case NOT_GRANTEE = 'not_grantee';
}
