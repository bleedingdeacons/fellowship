import * as logger from 'firebase-functions/logger';
import { GoogleAuth } from 'google-auth-library';

/**
 * Detaches billing when spending passes the budget.
 *
 * A budget only sends emails, so this is what actually stops the spending. It
 * puts the project back on the free plan, which stops Cloud Functions, so Link
 * cannot enrol or send until somebody attaches billing again. Receiving what is
 * already in Firestore keeps working within the free quota.
 *
 * Only actual spend counts. A forecast passing the budget says it might happen,
 * and is not worth taking the service down for.
 */

export interface BudgetAlert {
  costAmount?: number;
  budgetAmount?: number;
  /** Set only by a person testing this, never by a budget. See checkReadiness. */
  check?: boolean;
}

export function overBudget(alert: BudgetAlert): boolean {
  const cost = Number(alert.costAmount);
  const budget = Number(alert.budgetAmount);

  return Number.isFinite(cost) && Number.isFinite(budget) && budget > 0 && cost >= budget;
}

const BILLING_SCOPE = 'https://www.googleapis.com/auth/cloud-billing';

/** What this function needs in order to detach billing. */
const NEEDED_ON_BILLING_ACCOUNT = ['billing.resourceAssociations.delete'];
const NEEDED_ON_PROJECT = ['resourcemanager.projects.deleteBillingAssignment'];

/**
 * Says whether detaching would work, without detaching.
 *
 * Firing this for real can cost data, so it can't be tested by firing it. Publish
 * `{"check": true}` to the topic and read the function's log.
 */
export async function checkReadiness(projectId: string): Promise<void> {
  const client = await new GoogleAuth({ scopes: [BILLING_SCOPE, 'https://www.googleapis.com/auth/cloud-platform'] }).getClient();

  const info = await client.request<{ billingAccountName?: string; billingEnabled?: boolean }>({
    url: `https://cloudbilling.googleapis.com/v1/projects/${projectId}/billingInfo`,
  });

  const held = async (url: string, permissions: string[]): Promise<string[]> => {
    const answer = await client.request<{ permissions?: string[] }>({ url, method: 'POST', data: { permissions } });

    return permissions.filter((permission) => !(answer.data.permissions ?? []).includes(permission));
  };

  const missing = [
    ...(await held(
      `https://cloudbilling.googleapis.com/v1/${info.data.billingAccountName}:testIamPermissions`,
      NEEDED_ON_BILLING_ACCOUNT,
    )),
    ...(await held(
      `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:testIamPermissions`,
      NEEDED_ON_PROJECT,
    )),
  ];

  logger.info('Kill switch readiness check', {
    billingEnabled: info.data.billingEnabled === true,
    ready: missing.length === 0,
    missing,
  });
}

export async function detachBilling(projectId: string): Promise<void> {
  const client = await new GoogleAuth({ scopes: [BILLING_SCOPE] }).getClient();
  const url = `https://cloudbilling.googleapis.com/v1/projects/${projectId}/billingInfo`;

  const current = await client.request<{ billingEnabled?: boolean }>({ url });
  if (current.data.billingEnabled !== true) {
    return;
  }

  await client.request({ url, method: 'PUT', data: { billingAccountName: '' } });

  logger.error('Spending passed the budget, so billing was detached from the project');
}
