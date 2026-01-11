# Provenix デバッグガイド - クイックスタート

## 🚀 すぐに試す

### 1. サンプルプログラムで処理フローを確認

```bash
go run examples/debug_providers.go
```

**出力:**
- Step 1: プロバイダー登録
- Step 2: SBOM生成 (CycloneDX形式)
- Step 3: 脆弱性スキャン
- Step 4: 署名作成

全て成功すれば `All steps completed successfully!` と表示されます。

### 2. VS Codeでデバッグ

1. VS Codeで `examples/debug_providers.go` を開く
2. `F5` キーを押すか、「実行とデバッグ」パネルから **"Debug Provider System"** を選択
3. ブレークポイントを設定したい行番号の左側をクリック

**おすすめブレークポイント:**
- `internal/providers/sbom/mock/mock.go:60` - SBOM生成開始
- `internal/providers/scanner/mock/mock.go:67` - スキャン開始
- `internal/providers/signer/mock/mock.go:73` - 署名開始

### 3. テストの実行

```bash
# 全テスト
go test ./... -v

# Provider関連のみ
go test ./internal/providers/... -v

# カバレッジ付き
go test ./internal/providers/... -cover
```

## 📝 処理フローの概要

```
1. Provider Registration
   ├─ RegisterSBOMProvider("mock", mockProvider)
   ├─ RegisterScannerProvider("mock", mockProvider)
   └─ RegisterSignerProvider("mock", mockProvider)

2. SBOM Generation
   ├─ GetSBOMProvider("mock")
   ├─ provider.Generate(ctx, "nginx:latest", opts)
   └─ Returns: SBOM with checksum

3. Vulnerability Scanning
   ├─ GetScannerProvider("mock")
   ├─ provider.Scan(ctx, ScanInput{SBOM: sbom}, opts)
   └─ Returns: Report with vulnerabilities

4. Signature Creation
   ├─ GetSignerProvider("mock")
   ├─ Create in-toto Statement
   ├─ provider.Sign(ctx, statement, opts)
   └─ Returns: Signature with certificate/Rekor entry
```

## 🔍 詳細なデバッグ方法

詳しくは [docs/debugging.md](debugging.md) を参照してください。

---

**作成日:** 2026-01-12
