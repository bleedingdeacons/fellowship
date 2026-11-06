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
}

export function overBudget(alert: BudgetAlert): boolean {
  const cost = Number(alert.costAmount);
  const budget = Number(alert.budgetAmount);

  return Number.isFinite(cost) && Number.isFinite(budget) && budget > 0 && cost >= budget;
}

const BILLING_SCOPE = 'https://www.googleapis.com/auth/cloud-billing';

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
