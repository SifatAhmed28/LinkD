const { Octokit } = require('@octokit/rest');
const { parse } = require('tldts');
const logger = require('../utils/logger');

let octokit = null;

function getOctokit() {
  if (!octokit) {
    octokit = new Octokit({
      auth: process.env.GITHUB_TOKEN || undefined,
      userAgent: 'LinkD-PhishingDetector/1.0',
    });
  }
  return octokit;
}

/**
 * Extracts owner and repo from a GitHub URL.
 * Handles: github.com/owner/repo, github.io/repo, raw.githubusercontent.com/owner/repo/...
 *
 * @param {string} url
 * @returns {{ owner: string, repo: string }|null}
 */
function parseGitHubUrl(url) {
  try {
    const parsed = new URL(url);
    const { hostname, pathname } = parsed;
    const parts = pathname.replace(/^\//, '').split('/').filter(Boolean);

    if (hostname === 'github.com' && parts.length >= 2) {
      return { owner: parts[0], repo: parts[1] };
    }

    if (hostname === 'raw.githubusercontent.com' && parts.length >= 2) {
      return { owner: parts[0], repo: parts[1] };
    }

    // GitHub Pages: owner.github.io/repo
    if (hostname.endsWith('.github.io')) {
      const owner = hostname.replace('.github.io', '');
      const repo = parts[0] || null;
      return repo ? { owner, repo } : null;
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Analyzes a GitHub repository for phishing risk signals.
 *
 * @param {string} url - The full GitHub URL being scanned
 * @param {Object} parsedHtml - Output from htmlParser.parseHtml()
 * @returns {Promise<Object>} GitHub context signals
 */
async function analyzeGitHubContext(url, parsedHtml) {
  const result = {
    isGitHub: false,
    signals: {},
    githubScore: 0,
    flags: [],
  };

  const repoInfo = parseGitHubUrl(url);
  if (!repoInfo) return result;

  result.isGitHub = true;
  const { owner, repo } = repoInfo;
  const gh = getOctokit();

  try {
    // ── Fetch Repository Metadata ─────────────────────────────────────────
    const { data: repoData } = await gh.repos.get({ owner, repo });

    const createdAt = new Date(repoData.created_at);
    const ageDays = (Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24);

    result.signals.ageDays = Math.round(ageDays);
    result.signals.stars = repoData.stargazers_count;
    result.signals.forks = repoData.forks_count;
    result.signals.hasDescription = !!repoData.description;

    // ── Commit Count ──────────────────────────────────────────────────────
    let commitCount = 0;
    try {
      const { data: commits } = await gh.repos.listCommits({
        owner, repo, per_page: 10
      });
      // GitHub API returns up to per_page; for detecting < 3, this is enough
      commitCount = commits.length;
      result.signals.commitCount = commitCount;
    } catch {
      result.signals.commitCount = 'unknown';
    }

    // ── Contributor Count ─────────────────────────────────────────────────
    try {
      const { data: contributors } = await gh.repos.listContributors({
        owner, repo, per_page: 5
      });
      result.signals.contributorCount = contributors.length;
    } catch {
      result.signals.contributorCount = 'unknown';
    }

    // ── Scoring Logic ─────────────────────────────────────────────────────
    let score = 0;

    // Very new repo (< 7 days)
    if (ageDays < 7) {
      score += 0.4;
      result.flags.push('repo_very_new');
    } else if (ageDays < 30) {
      score += 0.15;
      result.flags.push('repo_recently_created');
    }

    // Minimal commit history
    if (typeof commitCount === 'number' && commitCount < 3) {
      score += 0.3;
      result.flags.push('very_few_commits');
    }

    // No description (common for quick phishing setup)
    if (!repoData.description) {
      score += 0.1;
      result.flags.push('no_description');
    }

    // Assign API-derived score to result before DOM analysis
    result.githubScore = score;

  } catch (err) {
    if (err.status === 404) {
      logger.warn(`GitHub repo not found: ${owner}/${repo}`);
      result.signals.repoNotFound = true;
      result.githubScore = 0.1;
      return result;
    }
    if (err.status === 403) {
      logger.warn('GitHub API rate limit hit. Set GITHUB_TOKEN in .env');
    } else {
      logger.warn(`GitHub API error: ${err.message}`);
    }
  }

  // ── DOM-Level Analysis (from parsed HTML) ─────────────────────────────
  if (parsedHtml) {
    // Password input in page content (critical for GitHub)
    if (parsedHtml.hasPasswordInput) {
      result.flags.push('password_input_on_github');
      result.signals.passwordInputInPage = true;

      // If this is a GitHub Pages site, password inputs are extremely suspicious
      if (url.includes('github.io') || url.includes('githubusercontent.com')) {
        result.signals.criticalPasswordInReadme = true;
        result.flags.push('CRITICAL_password_in_github_pages');
      }
    }

    // Form with cross-origin action on GitHub
    for (const form of (parsedHtml.forms || [])) {
      if (form.action && form.action.startsWith('http')) {
        try {
          const formOrigin = new URL(form.action).hostname;
          const pageOrigin = new URL(url).hostname;
          if (formOrigin !== pageOrigin) {
            result.flags.push('cross_origin_form_on_github');
            result.signals.crossOriginForm = form.action.substring(0, 100);
          }
        } catch { /* invalid form action URL */ }
      }
    }
  }

  // Recompute score with DOM signals
  let finalScore = result.githubScore || 0;
  if (result.signals.criticalPasswordInReadme) finalScore += 0.8;
  else if (result.signals.passwordInputInPage) finalScore += 0.5;
  if (result.signals.crossOriginForm) finalScore += 0.6;

  // Add base heuristic score
  const baseScore = result.flags
    .filter(f => ['repo_very_new', 'very_few_commits'].includes(f))
    .reduce((acc, f) => acc + (f === 'repo_very_new' ? 0.4 : 0.3), 0);

  result.githubScore = parseFloat(Math.min(finalScore + baseScore, 1.0).toFixed(3));

  logger.info(`GitHub context for ${owner}/${repo}: score=${result.githubScore}, flags=${result.flags.join(',')}`);
  return result;
}

module.exports = { analyzeGitHubContext, parseGitHubUrl };
