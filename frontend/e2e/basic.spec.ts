import { test, expect } from '@playwright/test';

test('homepage has correct title and elements', async ({ page }) => {
  await page.goto('http://localhost:3000');
  
  // Check title
  await expect(page).toHaveTitle(/RE-Architect/);
  
  // Check header exists
  const navbar = page.locator('header');
  await expect(navbar).toBeVisible();

  // Check for dashboard content
  await page.waitForSelector('text=Dashboard', { timeout: 5000 });
  
  // Check for sidebar navigation
  const sidebar = page.locator('nav');
  await expect(sidebar).toBeVisible();
});

test('navigation works correctly', async ({ page }) => {
  await page.goto('http://localhost:3000');
  
  // Navigate to Functions view
  await page.click('text=Functions');
  await page.waitForURL('**/functions');
  await page.waitForSelector('text=Function View');
  
  // Navigate to Data Structures view
  await page.click('text=Data Structures');
  await page.waitForURL('**/data-structures');
  await page.waitForSelector('text=Data Structure View');
  
  // Navigate back to Dashboard
  await page.click('text=Dashboard');
  await page.waitForURL('**/');
  await page.waitForSelector('text=Dashboard');
});

test('theme switching works', async ({ page }) => {
  await page.goto('http://localhost:3000');
  
  // Get the initial theme
  const initialTheme = await page.evaluate(() => {
    return document.documentElement.classList.contains('dark-mode');
  });
  
  // Click the theme toggle button
  await page.click('[aria-label="Toggle dark mode"]');
  
  // Check if the theme changed
  const newTheme = await page.evaluate(() => {
    return document.documentElement.classList.contains('dark-mode');
  });
  
  expect(newTheme).not.toBe(initialTheme);
});
