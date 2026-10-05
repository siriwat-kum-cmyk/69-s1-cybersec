import { factories } from '@strapi/strapi';

/**
 * Route Hardening & Attack Surface Reduction:
 * Exclude DELETE route completely to enforce Immutable Medical Records (Audit Compliance).
 * Only 'find', 'findOne', 'create', and 'update' are permitted.
 */
export default factories.createCoreRouter('api::medical-record.medical-record', {
  only: ['find', 'findOne', 'create', 'update'],
});

