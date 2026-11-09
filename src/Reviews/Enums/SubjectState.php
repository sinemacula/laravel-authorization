<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Enums;

/**
 * What a review knows of a row's subject: active, inactive (an identity that
 * reports itself inactive, or a record deleted softly), or unknown (a record
 * that cannot be found). A review lists an inactive subject's stored grants all
 * the same, though every check about it denies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum SubjectState: string
{
    /** The subject's record exists and is not inactive. */
    case ACTIVE = 'active';

    /** The subject, or its identity, reports itself inactive, or its record is deleted softly. */
    case INACTIVE = 'inactive';

    /** The subject's record cannot be found, or its type names no model. */
    case UNKNOWN = 'unknown';
}
