import * as logger from 'firebase-functions/logger';
import { GoogleAuth } from 'google-auth-library';
import { BILLING_ACCOUNT } from './config';

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
const NEEDED_ON_PROJECT = ['resourcemanager.projects.deleteBillingAssignment'];
const NEEDED_ON_BILLING_ACCOUNT = ['billing.resourceAssociations.delete'];

/**
 * Says whether detaching would work, without detaching.
 *
 * Firing this for real can cost data, so it can't be tested by firing it. Publish
 * `{"check": true}` to the topic and read the function's log. Each question is
 * answered separately, so one refusal doesn't hide the others.
 */
export async function checkReadiness(projectId: string): Promise<void> {
  const client = await new GoogleAuth({ scopes: [BILLING_SCOPE, 'https://www.googleapis.com/auth/cloud-platform'] }).getClient();
  const refusals: string[] = [];

  const missing = async (url: string, permissions: string[]): Promise<string[]> => {
    try {
      const answer = await client.request<{ permissions?: string[] }>({ url, method: 'POST', data: { permissions } });

      return permissions.filter((permission) => !(answer.data.permissions ?? []).includes(permission));
    } catch (error) {
      refusals.push(`${url}: ${String(error)}`);

      return permissions;
    }
  };

  const missingOnProject = await missing(
    `https://cloudresourcemanager.googleapis.com/v1/projects/${projectId}:testIamPermissions`,
    NEEDED_ON_PROJECT,
  );

  const missingOnAccount = await missing(
    `https://cloudbilling.googleapis.com/v1/${BILLING_ACCOUNT}:testIamPermissions`,
    NEEDED_ON_BILLING_ACCOUNT,
  );

  logger.info('Kill switch readiness check', {
    ready: missingOnProject.length === 0 && missingOnAccount.length === 0,
    missingOnProject,
    missingOnAccount,
    refusals,
  });
}

/**
 * Goes straight to the detach. Asking first would make firing depend on a
 * permission it doesn't otherwise need, and detaching twice is harmless.
 */
export async function detachBilling(projectId: string): Promise<void> {
  const client = await new GoogleAuth({ scopes: [BILLING_SCOPE] }).getClient();

  await client.request({
    url: `https://cloudbilling.googleapis.com/v1/projects/${projectId}/billingInfo`,
    method: 'PUT',
    data: { billingAccountName: '' },
  });

  logger.error('Spending passed the budget, so billing was detached from the project');
}
