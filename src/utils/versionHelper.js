const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');
const config = require('../config');

class VersionHelper {
  constructor() {
    this.packagePath = path.join(config.ROOT_DIR, 'package.json');
    this.publicDir = path.join(config.ROOT_DIR, 'public');
    this.cachedCommit = null;
    this.cachedVersion = null;
    this.cachedHashes = null;
    this.cachedAssetVersion = null;
    this.buildTime = new Date().toISOString();
    this.init();
  }

  init() {
    this.cachedCommit = this.resolveGitCommit();
    this.refresh();
  }

  /**
   * Resolve git commit short hash if available.
   */
  resolveGitCommit() {
    if (process.env.GIT_COMMIT) return process.env.GIT_COMMIT.slice(0, 7);
    if (process.env.COMMIT_SHA) return process.env.COMMIT_SHA.slice(0, 7);
    try {
      const commit = execSync('git rev-parse --short HEAD', {
        cwd: config.ROOT_DIR,
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 1000,
      }).toString().trim();
      if (commit && /^[0-9a-f]+$/i.test(commit)) return commit;
    } catch (_) {}
    return null;
  }

  /**
   * Read package.json version.
   */
  getPackageVersion() {
    try {
      if (fs.existsSync(this.packagePath)) {
        const pkg = JSON.parse(fs.readFileSync(this.packagePath, 'utf8'));
        if (pkg.version) return pkg.version;
      }
    } catch (_) {}
    return '1.0.0';
  }

  /**
   * Compute MD5 hash of all regular files in a directory.
   * @param {string} dirPath
   * @returns {string}
   */
  hashDirectory(dirPath) {
    if (!fs.existsSync(dirPath)) return '';
    const hash = crypto.createHash('md5');
    try {
      const files = fs.readdirSync(dirPath, { withFileTypes: true })
        .filter((entry) => entry.isFile())
        .sort((a, b) => a.name.localeCompare(b.name));

      for (const file of files) {
        hash.update(file.name);
        try {
          const content = fs.readFileSync(path.join(dirPath, file.name));
          hash.update(content);
        } catch (_) {}
      }
      return hash.digest('hex').slice(0, 8);
    } catch (_) {
      return '';
    }
  }

  /**
   * Refresh version calculations from disk.
   */
  refresh() {
    this.cachedVersion = process.env.APP_VERSION || this.getPackageVersion();

    const cssHash = this.hashDirectory(path.join(this.publicDir, 'css'));
    const assetsHash = this.hashDirectory(path.join(this.publicDir, 'assets'));
    const customHash = this.hashDirectory(path.join(this.publicDir, 'custom'));

    // Hash sw.js if present
    let swHash = '';
    const swPath = path.join(this.publicDir, 'sw.js');
    if (fs.existsSync(swPath)) {
      try {
        swHash = crypto.createHash('md5').update(fs.readFileSync(swPath)).digest('hex').slice(0, 8);
      } catch (_) {}
    }

    const combinedHash = crypto.createHash('md5')
      .update(cssHash || '')
      .update(assetsHash || '')
      .update(customHash || '')
      .update(swHash || '')
      .digest('hex')
      .slice(0, 8);

    this.cachedHashes = {
      css: cssHash,
      assets: assetsHash,
      custom: customHash,
      sw: swHash,
      combined: combinedHash,
    };

    // Semantic asset version: <semver>.<commit>.<contentHash>
    const parts = [this.cachedVersion];
    if (this.cachedCommit) parts.push(this.cachedCommit);
    if (combinedHash) parts.push(combinedHash);

    this.cachedAssetVersion = parts.join('.');
    return this.cachedAssetVersion;
  }

  get version() {
    return this.cachedVersion || this.getPackageVersion();
  }

  get commit() {
    return this.cachedCommit;
  }

  get assetVersion() {
    return this.cachedAssetVersion || this.refresh();
  }

  get cacheName() {
    return `auth-gateway-v${this.cachedAssetVersion}`;
  }

  /**
   * Append version query parameter to an asset URL if not already present.
   * @param {string} url
   * @returns {string}
   */
  withVersion(url) {
    if (!url || typeof url !== 'string') return url;
    if (url.includes('?v=') || url.includes('&v=')) return url;
    const separator = url.includes('?') ? '&' : '?';
    return `${url}${separator}v=${encodeURIComponent(this.assetVersion)}`;
  }

  /**
   * Get full metadata for diagnostics and health endpoints.
   */
  getMetadata() {
    return {
      version: this.version,
      commit: this.commit,
      assetVersion: this.assetVersion,
      cacheName: this.cacheName,
      buildTime: this.buildTime,
      hashes: this.cachedHashes,
    };
  }
}

module.exports = new VersionHelper();
