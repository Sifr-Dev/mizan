import { test, expect } from '@playwright/test';

const user = {
  id: 'user-1',
  name: 'Browser User',
  email: 'browser@example.test',
  role: 'user',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

function authPayload() {
  return { success: true, data: { access_token: 'browser-access', user } };
}

test('login reaches the protected dashboard and logout returns to sign-in', async ({ page }) => {
  await page.route('**/api/v1/auth/refresh', async route => {
    await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: 'no session' }) });
  });
  await page.route('**/api/v1/auth/login', async route => {
    expect(route.request().postDataJSON()).toEqual({ email: user.email, password: 'correct horse battery staple' });
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(authPayload()) });
  });
  await page.route('**/api/v1/auth/logout', async route => {
    await route.fulfill({ status: 204 });
  });
  await page.route('**/api/v1/tasks', async route => {
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true, data: [] }) });
  });

  await page.goto('/login');
  await page.getByLabel('Email').fill(user.email);
  await page.getByLabel('Password').fill('correct horse battery staple');
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText('GoClean', { exact: true })).toBeVisible();
  await expect(page.getByText(user.email, { exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Logout', exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);
});
