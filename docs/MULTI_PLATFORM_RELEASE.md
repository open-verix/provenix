# Multi-Platform Release - Quick Start Guide

このガイドは、Provenixのマルチプラットフォームビルド・リリース機能を説明します。

## 📦 対応プラットフォーム

GoReleaserを使って、以下のプラットフォーム向けバイナリを自動生成します：

| OS      | Architecture | Binary Name      | Package Format |
|---------|-------------|------------------|----------------|
| Linux   | amd64       | provenix         | tar.gz         |
| Linux   | arm64       | provenix         | tar.gz         |
| macOS   | amd64       | provenix         | tar.gz         |
| macOS   | arm64       | provenix         | tar.gz         |
| Windows | amd64       | provenix.exe     | zip            |

## 🚀 ローカルでテストする

### 1. GoReleaserのインストール

```bash
# macOS
brew install goreleaser

# Linux (Debian/Ubuntu)
echo 'deb [trusted=yes] https://repo.goreleaser.com/apt/ /' | sudo tee /etc/apt/sources.list.d/goreleaser.list
sudo apt update
sudo apt install goreleaser

# またはMakefileを使用
make install-goreleaser
```

### 2. ローカルでビルドテスト

```bash
# 全プラットフォーム向けにビルド（リリースなし）
make build-all

# 結果を確認
ls -lh dist/

# 出力例:
# dist/provenix_linux_amd64_v1/provenix
# dist/provenix_linux_arm64/provenix
# dist/provenix_darwin_amd64_v1/provenix
# dist/provenix_darwin_arm64/provenix
# dist/provenix_windows_amd64_v1/provenix.exe
```

### 3. スナップショットリリースのテスト

```bash
# リリースプロセス全体をテスト（GitHub公開なし）
make release-local

# 生成されたアーカイブを確認
ls -lh dist/*.tar.gz dist/*.zip

# チェックサムを確認
cat dist/checksums.txt
```

### 4. 特定のプラットフォームをテスト

```bash
# macOS (Apple Silicon) のみ
GOOS=darwin GOARCH=arm64 go build -o provenix-mac-arm64 ./cmd/provenix

# Linux (amd64) のみ
GOOS=linux GOARCH=amd64 go build -o provenix-linux-amd64 ./cmd/provenix

# Windows (amd64 cross-compile from macOS/Linux)
GOOS=windows GOARCH=amd64 go build -o provenix-windows-amd64.exe ./cmd/provenix
```

## 📤 GitHubリリースの作成

### 方法1: Gitタグでトリガー（推奨）

```bash
# 1. バージョンタグを作成
git tag v0.1.0-alpha.2
git push origin v0.1.0-alpha.2

# 2. GitHub Actionsが自動実行
# - 全プラットフォームでビルド
# - テスト実行
# - GitHub Releasesに公開
# - チェックサム生成
# - Dockerイメージビルド（オプション）

# 3. リリースを確認
open https://github.com/open-verix/provenix/releases
```

### 方法2: 手動トリガー

```bash
# GitHub UI から workflow_dispatch でトリガー
# Settings → Actions → Release Multi-Platform Binaries → Run workflow
```

### 方法3: ローカルから直接リリース（要注意）

```bash
# GitHub Token が必要
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxx"

# リリース実行
goreleaser release --clean

# または
make release-snapshot
```

## 🔍 リリース後の確認

### ダウンロードリンクの確認

リリース後、以下のURLでバイナリがダウンロード可能になります：

```
https://github.com/open-verix/provenix/releases/download/v0.1.0-alpha.2/provenix_v0.1.0-alpha.2_darwin_arm64.tar.gz
https://github.com/open-verix/provenix/releases/download/v0.1.0-alpha.2/provenix_v0.1.0-alpha.2_darwin_amd64.tar.gz
https://github.com/open-verix/provenix/releases/download/v0.1.0-alpha.2/provenix_v0.1.0-alpha.2_linux_amd64.tar.gz
https://github.com/open-verix/provenix/releases/download/v0.1.0-alpha.2/provenix_v0.1.0-alpha.2_linux_arm64.tar.gz
https://github.com/open-verix/provenix/releases/download/v0.1.0-alpha.2/provenix_v0.1.0-alpha.2_windows_amd64.zip
https://github.com/open-verix/provenix/releases/download/v0.1.0-alpha.2/checksums.txt
```

### インストールスクリプトのテスト

```bash
# macOS/Linux
curl -fsSL https://raw.githubusercontent.com/open-verix/provenix/main/scripts/install.sh | bash

# Windows (PowerShell)
iwr -useb https://raw.githubusercontent.com/open-verix/provenix/main/scripts/install.ps1 | iex
```

## 🛠️ トラブルシューティング

### GoReleaserエラー: "no snapshot version"

```bash
# .goreleaser.yml の snapshot セクションを確認
snapshot:
  name_template: "{{ incpatch .Version }}-next"
```

### ビルドエラー: "CGO_ENABLED"

```bash
# .goreleaser.yml で CGO を無効化
env:
  - CGO_ENABLED=0
```

### GitHub Actionsエラー: "permission denied"

```yaml
# .github/workflows/release.yml で permissions を確認
permissions:
  contents: write  # リリース作成に必要
  packages: write  # Docker imageに必要
```

### macOS: "cannot be opened because the developer cannot be verified"

```bash
# ユーザーに以下を案内
sudo xattr -d com.apple.quarantine /usr/local/bin/provenix
```

## 📊 CI/CDワークフロー図

```
┌─────────────────┐
│  git tag vX.Y.Z │
│  git push --tags│
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│ GitHub Actions Triggered    │
│ (.github/workflows/release) │
└────────┬────────────────────┘
         │
         ├──► Run Tests
         │
         ├──► GoReleaser Build
         │    ├─► Linux amd64
         │    ├─► Linux arm64
         │    ├─► macOS amd64
         │    ├─► macOS arm64
         │    └─► Windows amd64
         │
         ├──► Generate Checksums
         │
         ├──► Create GitHub Release
         │
         ├──► Upload Artifacts
         │
         └──► Build Docker Images (optional)
              ├─► linux/amd64
              └─► linux/arm64
```

## 🎯 次のステップ

1. **初回リリース:**
   ```bash
   git tag v0.1.0-alpha.2
   git push origin v0.1.0-alpha.2
   ```

2. **リリースノート編集:**
   - GitHub Releases ページで自動生成されたリリースノートを確認・編集

3. **provenix-examplesの更新:**
   - 新しいバージョンのインストール手順を provenix-examples に追加
   - CI/CDワークフローで新バージョンを使用

4. **ドキュメント更新:**
   - README.md にインストール手順を追加
   - INSTALLATION.md を更新

## 📚 参考資料

- [GoReleaser Documentation](https://goreleaser.com/)
- [GitHub Actions - Creating Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
- [Cross-Compilation in Go](https://go.dev/doc/install/source#environment)
