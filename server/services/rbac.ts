/**
 * Role-Based Access Control (RBAC) service
 */

import { createClient } from '@supabase/supabase-js';
import { cacheHelpers } from '../utils/redis';
import { logger } from '../utils/logger';

const supabase = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

// Permission definitions
export const PERMISSIONS = {
  // Company management
  'company:view': 'View company information',
  'company:edit': 'Edit company information',
  'company:delete': 'Delete company',

  // User management
  'users:view': 'View users',
  'users:create': 'Create users',
  'users:edit': 'Edit users',
  'users:delete': 'Delete users',
  'users:activate': 'Activate/deactivate users',

  // Contracts management
  'contracts:view': 'View contracts',
  'contracts:create': 'Create contracts',
  'contracts:edit': 'Edit contracts',
  'contracts:delete': 'Delete contracts',
  'contracts:approve': 'Approve contracts',
  'contracts:cancel': 'Cancel contracts',

  // Customers management
  'customers:view': 'View customers',
  'customers:create': 'Create customers',
  'customers:edit': 'Edit customers',
  'customers:delete': 'Delete customers',

  // Vehicles management
  'vehicles:view': 'View vehicles',
  'vehicles:create': 'Create vehicles',
  'vehicles:edit': 'Edit vehicles',
  'vehicles:delete': 'Delete vehicles',
  'vehicles:assign': 'Assign vehicles to contracts',

  // Employees management
  'employees:view': 'View employees',
  'employees:create': 'Create employees',
  'employees:edit': 'Edit employees',
  'employees:delete': 'Delete employees',

  // Violations management
  'violations:view': 'View violations',
  'violations:create': 'Create violations',
  'violations:edit': 'Edit violations',
  'violations:delete': 'Delete violations',
  'violations:resolve': 'Resolve violations',

  // Invoices management
  'invoices:view': 'View invoices',
  'invoices:create': 'Create invoices',
  'invoices:edit': 'Edit invoices',
  'invoices:delete': 'Delete invoices',
  'invoices:approve': 'Approve invoices',
  'invoices:pay': 'Mark invoices as paid',

  // Reports and analytics
  'reports:view': 'View reports',
  'reports:export': 'Export reports',
  'analytics:view': 'View analytics',

  // Dashboard
  'dashboard:view': 'View dashboard',

  // System administration
  'system:settings': 'Manage system settings',
  'system:logs': 'View system logs',
  'system:backup': 'Manage backups',
  'system:maintenance': 'Perform system maintenance',
} as const;

// Role definitions with their permissions
export const ROLES = {
  super_admin: Object.keys(PERMISSIONS), // All permissions

  admin: [
    // Company management
    'company:view', 'company:edit',

    // User management (except super admin operations)
    'users:view', 'users:create', 'users:edit', 'users:activate',

    // Full contracts management
    'contracts:view', 'contracts:create', 'contracts:edit', 'contracts:approve', 'contracts:cancel',

    // Full customers management
    'customers:view', 'customers:create', 'customers:edit', 'customers:delete',

    // Full vehicles management
    'vehicles:view', 'vehicles:create', 'vehicles:edit', 'vehicles:delete', 'vehicles:assign',

    // Full employees management
    'employees:view', 'employees:create', 'employees:edit', 'employees:delete',

    // Full violations management
    'violations:view', 'violations:create', 'violations:edit', 'violations:delete', 'violations:resolve',

    // Full invoices management
    'invoices:view', 'invoices:create', 'invoices:edit', 'invoices:approve', 'invoices:pay',

    // Reports and analytics
    'reports:view', 'reports:export', 'analytics:view',

    // Dashboard
    'dashboard:view',
  ],

  manager: [
    // View company info
    'company:view',

    // Basic user management
    'users:view', 'users:create', 'users:edit',

    // Contracts management (except deletion)
    'contracts:view', 'contracts:create', 'contracts:edit', 'contracts:approve',

    // Customers management
    'customers:view', 'customers:create', 'customers:edit',

    // Vehicles management
    'vehicles:view', 'vehicles:create', 'vehicles:edit', 'vehicles:assign',

    // Employees management
    'employees:view', 'employees:create', 'employees:edit',

    // Violations management
    'violations:view', 'violations:create', 'violations:edit', 'violations:resolve',

    // Invoices management
    'invoices:view', 'invoices:create', 'invoices:edit', 'invoices:approve',

    // Reports
    'reports:view', 'analytics:view',

    // Dashboard
    'dashboard:view',
  ],

  operator: [
    // View company info
    'company:view',

    // View users only
    'users:view',

    // Basic contracts operations
    'contracts:view', 'contracts:create', 'contracts:edit',

    // View and create customers
    'customers:view', 'customers:create',

    // View and create vehicles
    'vehicles:view', 'vehicles:create', 'vehicles:edit',

    // View employees
    'employees:view',

    // Violations management
    'violations:view', 'violations:create', 'violations:edit',

    // View invoices
    'invoices:view',

    // Dashboard
    'dashboard:view',
  ],

  viewer: [
    // Read-only access
    'company:view',
    'users:view',
    'contracts:view',
    'customers:view',
    'vehicles:view',
    'employees:view',
    'violations:view',
    'invoices:view',
    'dashboard:view',
  ],
} as const;

type Role = keyof typeof ROLES;
type Permission = keyof typeof PERMISSIONS;

/**
 * Get user permissions based on their role
 */
export async function getUserPermissions(userId: string, companyId: string): Promise<string[]> {
  const cacheKey = `user_permissions:${userId}:${companyId}`;

  try {
    // Try to get from cache first
    const cached = await cacheHelpers.get(cacheKey);
    if (cached) {
      return JSON.parse(cached);
    }

    // Get user profile with role
    const { data: profile, error } = await supabase
      .from('profiles')
      .select('role, custom_permissions')
      .eq('id', userId)
      .eq('company_id', companyId)
      .single();

    if (error || !profile) {
      logger.warn('User not found for permission check', { userId, companyId, error });
      return [];
    }

    // Get base permissions for role
    let permissions = ROLES[profile.role as Role] || [];

    // Add custom permissions if any
    if (profile.custom_permissions && Array.isArray(profile.custom_permissions)) {
      permissions = [...permissions, ...profile.custom_permissions];
    }

    // Remove duplicates
    permissions = [...new Set(permissions)];

    // Cache for 30 minutes
    await cacheHelpers.set(cacheKey, JSON.stringify(permissions), 30 * 60);

    return permissions;
  } catch (error) {
    logger.error('Error getting user permissions', { userId, companyId, error });
    return [];
  }
}

/**
 * Check if user has specific permission
 */
export async function hasPermission(
  userId: string,
  companyId: string,
  permission: string
): Promise<boolean> {
  const permissions = await getUserPermissions(userId, companyId);
  return permissions.includes(permission);
}

/**
 * Check if user has any of the specified permissions
 */
export async function hasAnyPermission(
  userId: string,
  companyId: string,
  permissions: string[]
): Promise<boolean> {
  const userPermissions = await getUserPermissions(userId, companyId);
  return permissions.some(permission => userPermissions.includes(permission));
}

/**
 * Check if user has all specified permissions
 */
export async function hasAllPermissions(
  userId: string,
  companyId: string,
  permissions: string[]
): Promise<boolean> {
  const userPermissions = await getUserPermissions(userId, companyId);
  return permissions.every(permission => userPermissions.includes(permission));
}

/**
 * Check if user has specific role or higher
 */
export function hasMinimumRole(userRole: string, minimumRole: string): boolean {
  const roleHierarchy = ['viewer', 'operator', 'manager', 'admin', 'super_admin'];
  const userIndex = roleHierarchy.indexOf(userRole);
  const minIndex = roleHierarchy.indexOf(minimumRole);

  return userIndex >= minIndex;
}

/**
 * Grant custom permission to user
 */
export async function grantCustomPermission(
  userId: string,
  permission: string
): Promise<void> {
  try {
    const { data: profile } = await supabase
      .from('profiles')
      .select('custom_permissions')
      .eq('id', userId)
      .single();

    if (!profile) {
      throw new Error('User not found');
    }

    const customPermissions = profile.custom_permissions || [];
    if (!customPermissions.includes(permission)) {
      customPermissions.push(permission);

      await supabase
        .from('profiles')
        .update({ custom_permissions })
        .eq('id', userId);

      // Clear cache for this user
      await cacheHelpers.del(`user_permissions:${userId}:*`);
    }

    logger.info('Custom permission granted', { userId, permission });
  } catch (error) {
    logger.error('Error granting custom permission', { userId, permission, error });
    throw error;
  }
}

/**
 * Revoke custom permission from user
 */
export async function revokeCustomPermission(
  userId: string,
  permission: string
): Promise<void> {
  try {
    const { data: profile } = await supabase
      .from('profiles')
      .select('custom_permissions')
      .eq('id', userId)
      .single();

    if (!profile) {
      throw new Error('User not found');
    }

    const customPermissions = (profile.custom_permissions || []).filter(
      (p: string) => p !== permission
    );

    await supabase
      .from('profiles')
      .update({ custom_permissions })
      .eq('id', userId);

    // Clear cache for this user
    await cacheHelpers.del(`user_permissions:${userId}:*`);

    logger.info('Custom permission revoked', { userId, permission });
  } catch (error) {
    logger.error('Error revoking custom permission', { userId, permission, error });
    throw error;
  }
}

/**
 * Get all available permissions with descriptions
 */
export function getAllPermissions(): Record<string, string> {
  return PERMISSIONS;
}

/**
 * Get all available roles with their permissions
 */
export function getAllRoles(): Record<string, string[]> {
  return ROLES;
}