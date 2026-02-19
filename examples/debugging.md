# Debugging Provenix

このドキュメントでは、Provenix の処理フローをデバッグする方法を説明します。

## 1. サンプルプログラムでの確認

最も簡単な方法は、用意されたデバッグプログラムを実行することです：

```bash
# Provider抽象化層の動作を確認
go run examples/debug_providers.go
```

**出力例:**

```
=== Provenix Provider System Debug ===

Step 1: Registering providers...
  ✓ Registered SBOM provider: mock
  ✓ Registered Scanner provider: mock
  ✓ Registered Signer provider: mock

Step 2: Generating SBOM...
  Artifact: nginx:latest
  Format: cyclonedx-json
  Provider: mock v1.0.0

  SBOM Details:
    Format: cyclonedx-json
    Artifact: nginx:latest
    Checksum: d9dfc8a2da67f05c19808613d05fad08d0d50cf966609c32a780a73fef10a630
    ...

Step 3: Scanning vulnerabilities...
  ...

Step 4: Creating signature...
  ...

=== All steps completed successfully! ===
```

## 2. VS Code デバッガーを使用

### 2.1 launch.json の設定

`.vscode/launch.json` を作成：

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug Providers",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/examples/debug_providers.go"
    },
    {
      "name": "Debug CLI",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/cmd/provenix",
      "args": ["attest", "nginx:latest"]
    },
    {
      "name": "Debug Tests",
      "type": "go",
      "request": "launch",
      "mode": "test",
      "program": "${workspaceFolder}/internal/providers",
      "args": ["-v"]
    }
  ]
}
```

### 2.2 ブレークポイントの設定

1. VS Code で対象ファイルを開く（例: `internal/providers/sbom/mock/mock.go`）
2. 行番号の左側をクリックしてブレークポイントを設定
3. `F5` または「実行とデバッグ」パネルから起動

**主要なブレークポイント位置:**

- `internal/providers/registry.go:30` - プロバイダー登録
- `internal/providers/sbom/mock/mock.go:60` - SBOM 生成
- `internal/providers/scanner/mock/mock.go:67` - 脆弱性スキャン
- `internal/providers/signer/mock/mock.go:73` - 署名作成

## 3. ログ出力での確認

### 3.1 標準的なログ出力

コードに `fmt.Printf` を追加：

```go
func (p *Provider) Generate(ctx context.Context, artifact string, opts sbom.Options) (*sbom.SBOM, error) {
    fmt.Printf("[DEBUG] Generating SBOM for artifact: %s, format: %s\n", artifact, opts.Format)

    // 処理...

    fmt.Printf("[DEBUG] SBOM generated with checksum: %s\n", checksum)
    return sbom, nil
}
```

### 3.2 Logrus を使用した構造化ログ

```go
import log "github.com/sirupsen/logrus"

func (p *Provider) Generate(ctx context.Context, artifact string, opts sbom.Options) (*sbom.SBOM, error) {
    log.WithFields(log.Fields{
        "artifact": artifact,
        "format":   opts.Format,
        "local":    opts.Local,
    }).Debug("Starting SBOM generation")

    // 処理...

    log.WithFields(log.Fields{
        "checksum": checksum,
        "size":     len(content),
    }).Info("SBOM generation completed")

    return sbom, nil
}
```

ログレベルを設定：

```bash
# DEBUGレベルで実行
LOG_LEVEL=debug go run examples/debug_providers.go

# INFOレベルで実行（デフォルト）
go run examples/debug_providers.go
```

## 4. テストでの確認

### 4.1 単体テストの実行

```bash
# すべてのテストを実行
go test ./... -v

# 特定のパッケージのみ
go test ./internal/providers/... -v

# 特定のテストのみ
go test ./internal/providers -run TestRegisterAndGetSBOMProvider -v

# カバレッジ付き
go test ./internal/providers/... -cover -v
```

### 4.2 テストに詳細ログを追加

```go
func TestSBOMGeneration(t *testing.T) {
    provider := sbomMock.NewProvider()

    t.Log("Creating context with 30s timeout")
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    t.Log("Generating SBOM for nginx:latest")
    sbom, err := provider.Generate(ctx, "nginx:latest", sbom.DefaultOptions())

    if err != nil {
        t.Fatalf("Generate failed: %v", err)
    }

    t.Logf("SBOM generated: format=%s, checksum=%s", sbom.Format, sbom.Checksum)
}
```

実行時に `-v` フラグを付けると `t.Log` の出力が表示されます。

## 5. Delve デバッガー（CLI）

### 5.1 Delve のインストール

```bash
go install github.com/go-delve/delve/cmd/dlv@latest
```

### 5.2 デバッグ実行

```bash
# プログラムをデバッグモードで起動
dlv debug examples/debug_providers.go

# (dlv) プロンプトが表示される
(dlv) break sbom.(*Provider).Generate  # ブレークポイント設定
(dlv) continue                          # 実行開始
(dlv) print artifact                    # 変数の値を表示
(dlv) step                              # ステップ実行
(dlv) next                              # 次の行へ
(dlv) continue                          # 次のブレークポイントまで実行
(dlv) quit                              # 終了
```

### 5.3 テストをデバッグ

```bash
cd internal/providers
dlv test

(dlv) break TestRegisterAndGetSBOMProvider
(dlv) continue
```

## 6. プロファイリング

### 6.1 CPU プロファイリング

```go
import (
    "os"
    "runtime/pprof"
)

func main() {
    // CPUプロファイル開始
    f, _ := os.Create("cpu.prof")
    defer f.Close()
    pprof.StartCPUProfile(f)
    defer pprof.StopCPUProfile()

    // 通常の処理
    // ...
}
```

プロファイル結果の確認：

```bash
go tool pprof cpu.prof
(pprof) top10
(pprof) web  # ブラウザでグラフ表示
```

### 6.2 メモリプロファイリング

```go
import (
    "os"
    "runtime/pprof"
)

func main() {
    // 通常の処理
    // ...

    // メモリプロファイル
    f, _ := os.Create("mem.prof")
    defer f.Close()
    pprof.WriteHeapProfile(f)
}
```

## 7. カスタムデバッグプログラムの作成

`examples/` ディレクトリに独自のデバッグプログラムを作成できます：

```go
// examples/my_debug.go
package main

import (
    "context"
    "fmt"

    "github.com/open-verix/provenix/internal/providers"
    sbomMock "github.com/open-verix/provenix/internal/providers/sbom/mock"
)

func main() {
    // 1. 特定のシナリオをテスト
    testCycloneDXFormat()
    testSPDXFormat()
    testSyftFormat()
}

func testCycloneDXFormat() {
    fmt.Println("Testing CycloneDX format...")

    provider := sbomMock.NewProvider()
    // ... テストコード
}
```

実行：

```bash
go run examples/my_debug.go
```

## 8. 実際のプロバイダー実装後のデバッグ

Syft/Grype/Cosign 実装後は、実際のコンテナイメージでテスト：

```bash
# 小さなイメージでテスト（高速）
./provenix attest alpine:latest

# 実際のアプリケーションイメージ
./provenix attest nginx:latest

# ローカルディレクトリ
./provenix attest --local ./myapp
```

## 9. トラブルシューティング

### 9.1 よくあるエラー

| エラー                      | 原因                   | 解決方法                                              |
| --------------------------- | ---------------------- | ----------------------------------------------------- |
| `provider not found`        | プロバイダー未登録     | `RegisterXXXProvider()` を呼び出す                    |
| `context deadline exceeded` | タイムアウト           | `context.WithTimeout()` の時間を延長                  |
| `invalid format`            | 不正なフォーマット指定 | `cyclonedx-json`, `spdx-json`, `syft-json` のいずれか |

### 9.2 デバッグのベストプラクティス

1. **小さなステップで確認**: 一度に 1 つのプロバイダーをテスト
2. **Mock から実装へ**: まず Mock で動作確認してから実装
3. **ログを活用**: 重要なポイントにログ出力を追加
4. **テストを書く**: バグ発見時はまずテストケースを追加
5. **エラーハンドリング**: エラーメッセージに十分なコンテキストを含める

## 10. 参考資料

- [Go Debugging with Delve](https://github.com/go-delve/delve/tree/master/Documentation)
- [VS Code Go Extension](https://code.visualstudio.com/docs/languages/go)
- [Effective Go - Testing](https://go.dev/doc/effective_go#testing)
- [pprof Documentation](https://pkg.go.dev/net/http/pprof)

---

**Last Updated:** 2026-01-12
