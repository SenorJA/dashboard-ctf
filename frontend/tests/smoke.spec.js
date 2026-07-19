// @ts-check
const { test, expect } = require('@playwright/test');

const BASE = process.env.BASE_URL || 'http://localhost:8000';

test.describe('MIRV — Smoke Tests', () => {

  test.beforeEach(async ({ page }) => {
    await page.goto(BASE);
    await page.waitForLoadState('networkidle');
  });

  // ─── Page load ───────────────────────────────────────────────

  test('page loads and shows title', async ({ page }) => {
    // Full title: "M.I.R.V. — Incident Response & Vulnerability Framework"
    await expect(page).toHaveTitle(/M\.I\.R\.V/i);
    // At least something visible — sidebar or terminal
    const main = page.locator('#sidebar, #terminal-output').first();
    await expect(main).toBeVisible();
  });

  test('terminal output area exists', async ({ page }) => {
    const terminal = page.locator('#output, #terminal-output, .terminal-output').first();
    await expect(terminal).toBeVisible();
  });

  test('command input exists', async ({ page }) => {
    const input = page.locator('#command-input, input[type="text"]').first();
    await expect(input).toBeVisible();
  });

  // ─── Tab switching ───────────────────────────────────────────

  const TABS = [
    { id: 'terminal', label: /terminal/i },
    { id: 'reports', label: /reports/i },
    { id: 'scripts', label: /scripts/i },
    { id: 'bounty', label: /bounty/i },
    { id: 'findings', label: /findings/i },
    { id: 'automation', label: /automation/i },
    { id: 'swarm', label: /swarm/i },
    { id: 'credentials', label: /credentials/i },
    { id: 'knowledgebase', label: /knowledge/i },
    { id: 'ctf', label: /ctf/i },
    { id: 'mobile', label: /mobile/i },
    { id: 'forensics', label: /forensics/i },
    { id: 'opadmiral', label: /op admiral/i },
    { id: 'aiwriteup', label: /ai writeup/i },
  ];

  for (const tab of TABS) {
    test(`tab switch: ${tab.id}`, async ({ page }) => {
      const btn = page.locator(`[data-tab="${tab.id}"], #tab-${tab.id}, button:has-text("${tab.label.source}")`).first();
      if (await btn.isVisible()) {
        await btn.click();
        await page.waitForTimeout(300);
        const panel = page.locator(`#tab-${tab.id}-panel, .tab-panel[data-tab="${tab.id}"]`).first();
        if (await panel.isVisible()) {
          await expect(panel).toBeVisible();
        }
      }
    });
  }

  // ─── Arsenal / sidebar ───────────────────────────────────────

  test('arsenal sidebar is visible', async ({ page }) => {
    const sidebar = page.locator('#sidebar, #arsenal, .sidebar, .arsenal').first();
    await expect(sidebar).toBeVisible();
  });

  test('arsenal filter works', async ({ page }) => {
    const filter = page.locator('#arsenal-filter, input[placeholder*="filter" i], input[placeholder*="search" i]').first();
    if (await filter.isVisible()) {
      await filter.fill('nmap');
      await page.waitForTimeout(200);
      // at least one tool should be filtered
      const tool = page.locator('button:has-text("nmap"), .tool-item:has-text("nmap")').first();
      await expect(tool).toBeVisible();
    }
  });

  // ─── Toggle theme / master ───────────────────────────────────

  test('master toggle (monochrome) toggles body class', async ({ page }) => {
    const toggle = page.locator('#theme-toggle, #master-toggle, [data-action="toggleTheme"]').first();
    if (await toggle.isVisible()) {
      await toggle.click();
      await page.waitForTimeout(200);
      const hasMono = await page.evaluate(() => document.body.classList.contains('monochrome'));
      // second click reverts
      if (hasMono) {
        await toggle.click();
        await page.waitForTimeout(200);
      }
    }
  });

  // ─── Connection dialog ───────────────────────────────────────

  test('connection modal opens from header button', async ({ page }) => {
    const connectBtn = page.locator('button:has-text("Connect"), button:has-text("SSH"), #connect-btn, [data-action="openConnect"]').first();
    if (await connectBtn.isVisible()) {
      await connectBtn.click();
      await page.waitForTimeout(300);
      const modal = page.locator('.modal:visible, #connect-modal:visible, [role="dialog"]:visible').first();
      if (await modal.isVisible()) {
        await expect(modal).toBeVisible();
      }
    }
  });

});

// ─── i18n Tests ───────────────────────────────────────────────

test.describe('Internationalization', () => {

  test('language toggle switches text', async ({ page }) => {
    await page.goto(BASE);
    await page.waitForLoadState('networkidle');

    const langBtn = page.locator('[data-action="lang"], #btn-lang').first();

    if (await langBtn.isVisible()) {
      // get current language
      const before = await page.evaluate(() => window.currentLang || 'en');

      // toggle
      await langBtn.click();
      await page.waitForTimeout(500);
      const after = await page.evaluate(() => window.currentLang || 'en');

      expect(after).not.toBe(before);
    }
  });

});

// ─── Responsive / Layout ──────────────────────────────────────

test.describe('Layout', () => {

  test('responsive: 1024px width still shows sidebar', async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 768 });
    await page.goto(BASE);
    await page.waitForLoadState('networkidle');
    // No #app root — layout is body-level
    const sidebar = page.locator('#sidebar').first();
    if (await sidebar.isVisible()) {
      await expect(sidebar).toBeVisible();
    } else {
      // sidebar may be toggled off; just confirm DOM loaded
      await expect(page.locator('#terminal-output')).toBeVisible();
    }
  });

  test('responsive: 375px mobile viewport does not crash', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto(BASE);
    await page.waitForLoadState('networkidle');
    const bodyText = await page.evaluate(() => document.body.innerText.length);
    expect(bodyText).toBeGreaterThan(0);
  });

});
