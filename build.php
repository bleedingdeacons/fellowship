#!/usr/bin/env php
<?php

/**
 * Build Script for Fellowship WordPress Plugin
 *
 * Cross-platform build script that works on Windows, macOS, and Linux.
 *
 * This script handles the compression and packaging of the plugin
 * for distribution.
 *
 * Usage: php build.php [target] [options]
 *
 * Targets:
 *   build:production   Create production archive (default)
 *   build:dev          Create development archive (includes tests)
 *   clean              Clean build directory only
 *
 * Options:
 *   --version=X.X      Override version number
 *   --clean            Clean build directory before building
 *   --help             Show this help message
 */

declare(strict_types=1);

class PluginBuilder
{
    private string $pluginDir;
    private string $buildDir;
    private string $version;
    private string $pluginName = 'fellowship';
    private bool $isWindows;

    // Files and directories to exclude in production builds
    private array $productionExcludes = [
        // Version control
            '.git',
            '.gitignore',
            '.gitattributes',

        // IDE/Editor
            '.idea',
            '.vscode',

        // Build artifacts
            'build',

        // Tests
            'tests',

        // OS files
            'node_modules',
            '.DS_Store',
            'Thumbs.db',

        // Composer files (not needed after autoload is generated)
            'composer.json',
            'composer.lock',

        // PHPUnit
            'phpunit.xml',
            'phpunit.xml.dist',
            '.phpunit.result.cache',

        // Code style
            '.phpcs.xml',
            '.phpcs.xml.dist',
            '.php-cs-fixer.php',
            '.php-cs-fixer.cache',

        // Static analysis
            'phpstan.neon',
            'phpstan.neon.dist',

        // Documentation
            '*.md',

        // Package manager
            'package.json',
            'package-lock.json',

        // Editor config
            '.editorconfig',

        // Build script
            'build.php',

        // Vendor (no production dependencies declared, but exclude defensively)
            'vendor',

            // Dev artefacts that must never ship
            '.phpunit.cache',
            'phpstan-baseline.neon',
            '.claude',
    ];

    // Files and directories to exclude in dev builds
    private array $devExcludes = [
        // Version control
            '.git',

        // IDE/Editor
            '.idea',
            '.vscode',

        // Build artifacts
            'build',

        // OS files
            'node_modules',
            '.DS_Store',
            'Thumbs.db',

        // PHPUnit runtime artefact — never useful in a distributed archive
            '.phpunit.result.cache',

        // ==== VENDOR DEV PACKAGES NOT NEEDED IN DEV BUILD ====
        // These are dev tools, not needed to run/test the plugin
            'vendor/bin',
            'vendor/phpstan',

        // Vendor unnecessary files
            'vendor/*/.git',
            'vendor/*/.github',
            'vendor/*/*/.github',
            'vendor/*/doc',
            'vendor/*/docs',
    ];

    public function __construct()
    {
        $this->isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $this->pluginDir = $this->normalizePath(dirname(__FILE__));
        $this->buildDir = $this->pluginDir . DIRECTORY_SEPARATOR . 'build';
        $this->version = $this->getVersionFromPlugin();

        // Check for required extensions
        $this->checkRequirements();
    }


    /**
     * Stage a clean production vendor/ for inclusion in the archive.
     *
     * Runs `composer install --no-dev --optimize-autoloader` against a copy of
     * composer.json / composer.lock in an isolated staging directory under
     * build/, so the developer's working vendor/ -- which holds phpunit,
     * phpstan and other test tooling -- is never mutated. Returns the absolute
     * path to the staged vendor/, or null when there is nothing to ship (no
     * composer.json, or no production dependencies).
     *
     * This replaces denylisting individual dev packages, which could only ever
     * be as current as the last time someone remembered to update the list.
     */
    private function stageProductionVendor(): ?string
    {
        $composerFile = $this->pluginDir . DIRECTORY_SEPARATOR . 'composer.json';
        if (!file_exists($composerFile)) {
            $this->log("No composer.json - production archive will ship no vendor/");
            return null;
        }

        $stagingDir = $this->buildDir . DIRECTORY_SEPARATOR . '.vendor-staging';
        if (is_dir($stagingDir)) {
            $this->deleteDirectory($stagingDir);
        }
        if (!is_dir($stagingDir) && !mkdir($stagingDir, 0755, true)) {
            $this->error("Failed to create vendor staging directory: {$stagingDir}");
            exit(1);
        }

        // Copy the dependency manifests so composer resolves the same set, and
        // the exact locked versions when a lock file is present.
        copy($composerFile, $stagingDir . DIRECTORY_SEPARATOR . 'composer.json');
        $lockFile = $this->pluginDir . DIRECTORY_SEPARATOR . 'composer.lock';
        if (file_exists($lockFile)) {
            copy($lockFile, $stagingDir . DIRECTORY_SEPARATOR . 'composer.lock');
        }

        $command = sprintf(
            'composer install --no-dev --optimize-autoloader --no-interaction --working-dir=%s 2>&1',
            escapeshellarg($stagingDir)
        );
        $this->log("Staging production vendor (no-dev)...");

        $output = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);

        if ($returnCode !== 0) {
            $this->error("Composer (no-dev) install failed with code {$returnCode}");
            foreach ($output as $line) {
                $this->error("  " . $line);
            }
            exit(1);
        }

        $stagedVendor = $stagingDir . DIRECTORY_SEPARATOR . 'vendor';
        if (!is_dir($stagedVendor)) {
            // No production dependencies were installed - nothing to ship.
            $this->log("No production dependencies - archive will ship no vendor/");
            return null;
        }

        $this->log("Staged production vendor/ (no-dev) ready");
        return $stagedVendor;
    }

    /**
     * Remove the vendor staging directory left by stageProductionVendor().
     */
    private function cleanVendorStaging(): void
    {
        $stagingDir = $this->buildDir . DIRECTORY_SEPARATOR . '.vendor-staging';
        if (is_dir($stagingDir)) {
            $this->deleteDirectory($stagingDir);
        }
    }

    /**
     * Normalize path separators for cross-platform compatibility
     */
    private function normalizePath(string $path): string
    {
        return str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $path);
    }

    /**
     * Check for required PHP extensions
     */
    private function checkRequirements(): void
    {
        if (!extension_loaded('zip')) {
            $this->error("PHP ZIP extension is required but not installed.");
            $this->error("Install it with:");
            if ($this->isWindows) {
                $this->error("  - Enable extension=zip in php.ini");
            } else {
                $this->error("  - Ubuntu/Debian: sudo apt-get install php-zip");
                $this->error("  - macOS: brew install php");
            }
            exit(1);
        }

        if (version_compare(PHP_VERSION, '8.1.0', '<')) {
            $this->error("PHP 8.1 or higher is required. Current version: " . PHP_VERSION);
            exit(1);
        }
    }

    /**
     * Extract version from the main plugin file
     */
    private function getVersionFromPlugin(): string
    {
        $mainFile = $this->pluginDir . DIRECTORY_SEPARATOR . 'fellowship.php';
        if (file_exists($mainFile)) {
            $content = file_get_contents($mainFile);
            if (preg_match('/Version:\s*([0-9.]+\s*\w*)/', $content, $matches)) {
                return trim($matches[1]);
            }
            if (preg_match("/define\s*\(\s*'FELLOWSHIP_VERSION'\s*,\s*'([^']+)'/", $content, $matches)) {
                return $matches[1];
            }
        }
        return '0.0.1';
    }

    /**
     * Clean the build directory
     */
    public function clean(): void
    {
        $this->log("Cleaning build directory...");
        if (is_dir($this->buildDir)) {
            $this->deleteDirectory($this->buildDir);
        }
        $this->log("Build directory cleaned");
    }

    /**
     * Create the plugin archive
     */
    public function build(string $type = 'production', ?string $customVersion = null): void
    {
        if ($customVersion) {
            $this->version = $customVersion;
        }

        $this->log("Building {$type} archive for version {$this->version}...");
        $this->log("Platform: " . PHP_OS . " (" . ($this->isWindows ? "Windows" : "Unix-like") . ")");

        // Check for vendor directory. Fellowship declares no production
        // dependencies, so a missing vendor/ is fine for a production
        // build — only run composer install when building a dev archive
        // that does want the dev tools available.
        $vendorDir = $this->pluginDir . DIRECTORY_SEPARATOR . 'vendor';
        if ($type === 'dev' && !is_dir($vendorDir)) {
            $this->log("vendor/ not found. Running 'composer install' for dev build...");
            $this->runComposer($type);
        }

        // Create build directory
        if (!is_dir($this->buildDir)) {
            if (!mkdir($this->buildDir, 0755, true)) {
                $this->error("Failed to create build directory: {$this->buildDir}");
                exit(1);
            }
        }

        // Determine archive name and excludes
        $archiveName = $this->buildDir . DIRECTORY_SEPARATOR . $this->pluginName;
        if ($type === 'dev') {
            $archiveName .= '-dev';
            $excludes = $this->devExcludes;
        } else {
            $archiveName .= '-production';
            $excludes = $this->productionExcludes;
        }

        // Sanitize version for filename
        $safeVersion = preg_replace('/[^a-zA-Z0-9._-]/', '-', $this->version);
        $archiveName .= '-' . $safeVersion . '.zip';

        // Sync readme.txt Stable tag with plugin version
        $this->syncReadmeVersion();

        // Sync README.md version badge with plugin version
        $this->syncReadmeMarkdownVersion();

        // Stamp the build date into the main plugin header
        $this->syncBuildDate();

        // Stamp the plugin version into the bundled HTML docs
        $this->syncDocsVersion();

        // Create ZIP archive
        // Stage a clean production vendor/ (no dev tooling) without touching
        // the working vendor/ used for tests. Dev builds keep it as-is.
        $stagedVendor = $type === 'dev' ? null : $this->stageProductionVendor();

        $this->createZip($archiveName, $excludes, $stagedVendor);
        $this->cleanVendorStaging();

        // Display file size
        $this->log("Archive created successfully: " . basename($archiveName));
        $fileSize = filesize($archiveName);
        if ($fileSize !== false) {
            $size = $this->formatBytes($fileSize);
            $this->log("File size: {$size}");
        }
        $this->log("Location: {$archiveName}");
    }

    /**
     * Run composer install if vendor directory is missing. The $type
     * controls whether dev dependencies are installed: production
     * builds use --no-dev, dev builds keep them.
     */
    private function runComposer(string $type): void
    {
        $composerFile = $this->pluginDir . DIRECTORY_SEPARATOR . 'composer.json';
        if (!file_exists($composerFile)) {
            $this->error("composer.json not found. Cannot install dependencies.");
            exit(1);
        }

        $command = $type === 'dev'
            ? 'composer install --optimize-autoloader'
            : 'composer install --no-dev --optimize-autoloader';
        $this->log("Running: {$command}");

        $output = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);

        if ($returnCode !== 0) {
            $this->error("Composer install failed with code {$returnCode}");
            foreach ($output as $line) {
                $this->error("  " . $line);
            }
            exit(1);
        }

        $this->log("Composer dependencies installed successfully");
    }

    /**
     * Create a ZIP archive
     */
    private function createZip(string $archivePath, array $excludes, ?string $stagedVendor = null): void
    {
        $zip = new ZipArchive();

        $result = $zip->open($archivePath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        if ($result !== true) {
            $this->error("Failed to create ZIP archive (error code: {$result})");
            exit(1);
        }

        $files = $this->getFiles($this->pluginDir, $excludes);
        $fileCount = 0;

        foreach ($files as $file) {
            $relativePath = substr($file, strlen($this->pluginDir) + 1);
            if (is_file($file)) {
                // Normalize path to use forward slashes for ZIP standard compliance.
                // The ZIP file format specification requires forward slashes;
                // this ensures proper extraction on all platforms.
                $relativePath = str_replace('\\', '/', $relativePath);

                $zipPath = $this->pluginName . '/' . $relativePath;

                // Read file content and add as string to avoid keeping file
                // handles open (which causes failures on Windows with many files).
                $contents = file_get_contents($file);
                if ($contents === false) {
                    $this->error("Warning: Could not read file: {$file}");
                    continue;
                }
                $zip->addFromString($zipPath, $contents);
                $fileCount++;
            }
        }


        // Inject the staged production vendor/ (no dev tooling) under the
        // plugin's vendor/ path. The working vendor/ is excluded from the walk
        // above, so this is the only vendor/ that reaches the archive.
        if ($stagedVendor !== null && is_dir($stagedVendor)) {
            foreach ($this->getFiles($stagedVendor, []) as $stagedFile) {
                if (!is_file($stagedFile)) {
                    continue;
                }
                $stagedRelative = str_replace('\\', '/', substr($stagedFile, strlen($stagedVendor) + 1));
                $zip->addFile($stagedFile, $this->pluginName . '/vendor/' . $stagedRelative);
                $fileCount++;
            }
        }

        if (!$zip->close()) {
            $this->error("Failed to write ZIP archive to: {$archivePath}");
            exit(1);
        }

        $this->log("Added {$fileCount} files to archive");
    }

    /**
     * Get all files in directory, excluding specified patterns
     */
    private function getFiles(string $dir, array $excludes): array
    {
        $files = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            $path = $file->getPathname();
            $relativePath = substr($path, strlen($dir) + 1);

            // Check if file should be excluded
            if ($this->shouldExclude($relativePath, $excludes)) {
                continue;
            }

            $files[] = $path;
        }

        return $files;
    }

    /**
     * Check if a file path should be excluded
     */
    private function shouldExclude(string $path, array $excludes): bool
    {
        // Normalize path for comparison (use forward slashes)
        $normalizedPath = str_replace('\\', '/', $path);

        foreach ($excludes as $exclude) {
            $normalizedExclude = str_replace('\\', '/', $exclude);

            // Check for wildcard patterns (e.g., *.md)
            if (strpos($normalizedExclude, '*') !== false) {
                $pattern = str_replace('*', '.*', preg_quote($normalizedExclude, '/'));
                // Use case-insensitive matching (i flag) for wildcard patterns
                if (preg_match('/^' . $pattern . '$/i', $normalizedPath)) {
                    return true;
                }
                // Also check basename for file extensions (case-insensitive)
                if (preg_match('/' . $pattern . '$/i', basename($normalizedPath))) {
                    return true;
                }
            }

            // Check if path starts with exclude pattern
            if (strpos($normalizedPath, $normalizedExclude) === 0) {
                return true;
            }

            // Check if any part of the path matches
            if (strpos($normalizedPath, '/' . $normalizedExclude . '/') !== false) {
                return true;
            }

            // Check if path contains the exclude pattern as a directory
            if (strpos($normalizedPath, '/' . $normalizedExclude) !== false) {
                return true;
            }

            // Check exact match
            if ($normalizedPath === $normalizedExclude) {
                return true;
            }
        }
        return false;
    }

    /**
     * Update the Stable tag in readme.txt to match the current plugin version
     */
    private function syncReadmeVersion(): void
    {
        $readmeFile = $this->pluginDir . DIRECTORY_SEPARATOR . 'readme.txt';
        if (!file_exists($readmeFile)) {
            $this->log("No readme.txt found — skipping version sync");
            return;
        }

        $content = file_get_contents($readmeFile);
        if ($content === false) {
            $this->error("Failed to read readme.txt");
            return;
        }

        $updated = preg_replace(
            '/^Stable tag:[ \t]*[^\r\n]*(?=\r?$)/mi',
            'Stable tag: ' . $this->version,
            $content,
            -1,
            $count
        );

        if ($count > 0 && $updated !== null) {
            file_put_contents($readmeFile, $updated);
            $this->log("Updated readme.txt Stable tag to {$this->version}");
        } else {
            $this->log("No Stable tag found in readme.txt — skipping version sync");
        }
    }

    /**
     * Update the version badge in README.md to match the current plugin version.
     *
     * The badge is the canonical place the version appears in README.md. The
     * legacy **Version:** line is still rewritten where one exists, so a repo
     * that has not been converted keeps working.
     */
    private function syncReadmeMarkdownVersion(): void
    {
        $readmeFile = $this->pluginDir . DIRECTORY_SEPARATOR . 'README.md';
        if (!file_exists($readmeFile)) {
            $this->log("No README.md found — skipping version sync");
            return;
        }

        $content = file_get_contents($readmeFile);
        if ($content === false) {
            $this->error("Failed to read README.md");
            return;
        }

        $updated = preg_replace(
            '~(img\.shields\.io/badge/version-)[^-\s)]+(-blue)~',
            '${1}' . $this->version . '${2}',
            $content,
            -1,
            $badgeCount
        );

        if ($updated === null) {
            $this->error("Failed to rewrite the version badge in README.md");
            return;
        }

        $updated = preg_replace(
            '/^\*\*Version:\*\*[ \t]*[^\r\n]*(?=\r?$)/m',
            '**Version:** ' . $this->version,
            $updated,
            -1,
            $lineCount
        );

        if ($updated === null) {
            $this->error("Failed to rewrite the **Version:** line in README.md");
            return;
        }

        $count = $badgeCount + $lineCount;

        if ($count > 0) {
            file_put_contents($readmeFile, $updated);
            $this->log("Updated README.md version to {$this->version} ({$badgeCount} badge, {$lineCount} line)");
        } else {
            $this->log("No version badge or **Version:** line in README.md — skipping version sync");
        }
    }

    /**
     * Update the version chip in the bundled HTML documentation.
     *
     * Replaces the version token inside <span class="version">…</span> with the
     * current plugin version (prefixed with "v"), leaving any trailing text —
     * such as " · Fellowship & the Link app" — untouched.
     */
    private function syncDocsVersion(): void
    {
        $docFile = $this->pluginDir . DIRECTORY_SEPARATOR . 'assets'
            . DIRECTORY_SEPARATOR . 'docs' . DIRECTORY_SEPARATOR . 'fellowship.html';

        if (!file_exists($docFile)) {
            $this->log("No assets/docs/fellowship.html found — skipping doc version sync");
            return;
        }

        $content = file_get_contents($docFile);
        if ($content === false) {
            $this->error("Failed to read assets/docs/fellowship.html");
            return;
        }

        // Match the version token immediately after the opening span tag,
        // preserving the rest of the chip (e.g. " · Fellowship & the Link app").
        //
        // The trailing group consumes an optional suffix word, because
        // getVersionFromPlugin() can return one ("1.2.0 beta"): without it the
        // match would stop at the space, and each build would write the suffix
        // in again after the one already there.
        $updated = preg_replace(
            '/(<span class="version">\s*)v?[0-9][\w.\-]*(?:[ \t]+\w+)?/',
            '${1}v' . $this->version,
            $content,
            1,
            $count
        );

        if ($count > 0 && $updated !== null) {
            file_put_contents($docFile, $updated);
            $this->log("Updated assets/docs/fellowship.html version to v{$this->version}");
        } else {
            $this->log("No version chip found in assets/docs/fellowship.html — skipping doc version sync");
        }
    }

    /**
     * Update (or insert) the Build date in readme.txt.
     *
     * Writes the current date in Y/m/d format (e.g. 2026/01/12). If a
     * "Build date:" line already exists in readme.txt it is updated;
     * otherwise a new line is inserted immediately after the "Stable tag:"
     * line, preserving the file's existing line ending convention.
     */
    private function syncBuildDate(): void
    {
        $readmeFile = $this->pluginDir . DIRECTORY_SEPARATOR . 'readme.txt';
        if (!file_exists($readmeFile)) {
            $this->log("No readme.txt found — skipping build date sync");
            return;
        }

        $content = file_get_contents($readmeFile);
        if ($content === false) {
            $this->error("Failed to read readme.txt");
            return;
        }

        // Build timestamps reflect the build machine's wall clock, not UTC.
        // php.ini sets date.timezone=UTC, so a bare date() call reads an hour
        // behind during BST; the zone is stated explicitly here rather than
        // left to ini config, which differs per machine.
        $buildDate = (new DateTime('now', new DateTimeZone('Europe/London')))
            ->format('Y/m/d H:i:s');

        // First, try to update an existing "Build date:" line.
        // The tail is matched as [^\r\n]* with a lookahead, not .+$. In PCRE `.`
        // matches \r, so `.+$` swallows the carriage return of a CRLF line and the
        // replacement writes it back LF-only, leaving one mixed line ending behind.
        // `$` in multiline mode anchors before \n and not before \r, so the CR has
        // to be stepped over by a lookahead rather than matched, or nothing matches.
        $updated = preg_replace(
            '/^Build date:[ \t]*[^\r\n]*(?=\r?$)/mi',
            'Build date: ' . $buildDate,
            $content,
            1,
            $count
        );

        if ($count > 0 && $updated !== null) {
            file_put_contents($readmeFile, $updated);
            $this->log("Updated readme.txt Build date to {$buildDate}");
            return;
        }

        // No existing line — insert one right after the "Stable tag:" line,
        // preserving the file's line ending convention (\r\n or \n).
        $updated = preg_replace_callback(
            '/^(Stable tag:[ \t]*[^\r\n]*)(\r?\n)/mi',
            static function (array $m) use ($buildDate): string {
                return $m[1] . $m[2] . 'Build date: ' . $buildDate . $m[2];
            },
            $content,
            1,
            $count
        );

        if ($count > 0 && $updated !== null) {
            file_put_contents($readmeFile, $updated);
            $this->log("Inserted Build date {$buildDate} into readme.txt");
        } else {
            $this->log("No Stable tag line found in readme.txt — skipping build date sync");
        }
    }


    /**
     * Delete directory recursively (cross-platform)
     */
    private function deleteDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . DIRECTORY_SEPARATOR . $file;

            // Windows: Remove read-only attribute if present
            if ($this->isWindows && file_exists($path)) {
                chmod($path, 0777);
            }

            if (is_dir($path)) {
                $this->deleteDirectory($path);
            } else {
                if (!unlink($path)) {
                    $this->error("Failed to delete file: {$path}");
                }
            }
        }

        if (!rmdir($dir)) {
            $this->error("Failed to remove directory: {$dir}");
        }
    }

    /**
     * Format bytes to human readable format
     */
    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }
        return round($bytes, 2) . ' ' . $units[$i];
    }

    /**
     * Log message
     */
    private function log(string $message): void
    {
        echo "[BUILD] {$message}\n";
    }

    /**
     * Log error message
     */
    private function error(string $message): void
    {
        echo "[ERROR] {$message}\n";
    }

    /**
     * Display help message
     */
    public function showHelp(): void
    {
        $phpVersion = PHP_VERSION;
        $platform = PHP_OS;

        echo <<<HELP

Fellowship WordPress Plugin Build Script
===================================
Platform: {$platform}
PHP Version: {$phpVersion}

Usage: php build.php [target] [options]

Targets:
  build:production    Create production archive (default)
  build:dev           Create development archive (includes tests)
  clean               Clean build directory only

Options:
  --type=production   Create production archive (alternative syntax)
  --type=dev          Create development archive (alternative syntax)
  --version=X.X       Override version number (default: from plugin file)
  --clean             Clean build directory before building
  --help              Show this help message

Examples:
  php build.php build:production          # Build production archive
  php build.php build:dev                 # Build development archive
  php build.php build:production --clean  # Clean and build production
  php build.php build:dev --version=1.0   # Dev build with custom version
  php build.php clean                     # Only clean build directory
  php build.php --type=production         # Alternative: using --type flag
  php build.php                           # Default: production build

Composer Scripts (already in composer.json):
  composer build              # Same as build:production
  composer build:production
  composer build:dev
  composer build:clean

Files Excluded (Production):
  - Development files (.git, .idea, .vscode, tests, etc.)
  - Build configuration (composer.json, package.json, etc.)
  - Documentation (*.md files)
  - PHP tooling configs (phpunit.xml, phpstan.neon, etc.)

Files Excluded (Dev):
  - Only: .git, .idea, .vscode, build, node_modules, .DS_Store

Platform-Specific Notes:

HELP;

        if ($this->isWindows) {
            echo <<<WINDOWS
  Windows Detected:
  - Paths use backslashes (\\) automatically
  - Build directory: .\\build\\
  - If permission errors occur, run Command Prompt as Administrator
  - Ensure ZIP extension is enabled in php.ini (extension=zip)

WINDOWS;
        } else {
            echo <<<UNIX
  Unix-like System (macOS/Linux) Detected:
  - Paths use forward slashes (/)
  - Build directory: ./build/
  - Make script executable: chmod +x build.php
  - Then run directly: ./build.php [target] [options]
  - Or run via: php build.php [target] [options]

UNIX;
        }

        echo <<<NOTES

PSR-4 Autoloading:
  This plugin uses its own spl_autoload_register in fellowship.php for the
  Fellowship\\ namespace, mapping to src/. The build script does not generate
  a Composer autoloader for production; the plugin's bundled autoloader
  is sufficient.

  Namespace: Fellowship\\
  Source: src/

NOTES;
    }
}

// Parse command line arguments
$options = getopt('', ['type:', 'version:', 'clean', 'clean-only', 'help']);

// Check for target-style arguments (build:production, build:dev)
$target = null;
foreach ($argv as $arg) {
    if ($arg === 'build:production' || $arg === 'production') {
        $target = 'production';
    } elseif ($arg === 'build:dev' || $arg === 'dev') {
        $target = 'dev';
    }
}

$builder = new PluginBuilder();

// Handle help
if (isset($options['help']) || in_array('--help', $argv) || in_array('-h', $argv) || in_array('help', $argv)) {
    $builder->showHelp();
    exit(0);
}

// Handle clean-only
if (isset($options['clean-only']) || in_array('clean', $argv)) {
    $builder->clean();
    // If only 'clean' was passed without a build target, exit
    if ($target === null && !isset($options['type'])) {
        exit(0);
    }
}

// Handle clean before build
if (isset($options['clean'])) {
    $builder->clean();
}

// Determine build type: target style takes precedence, then --type option, then default
$type = $target ?? ($options['type'] ?? 'production');

// Version: prefer getopt's --version, but also scan $argv manually since
// getopt() stops parsing at the first non-option argument. That means
// `php build.php build:production --version=0.2.0` would silently miss
// the --version flag without this fallback.
$version = $options['version'] ?? null;
if ($version === null) {
    foreach ($argv as $arg) {
        if (preg_match('/^--version=(.+)$/', $arg, $m)) {
            $version = $m[1];
            break;
        }
    }
}

$builder->build($type, $version);
