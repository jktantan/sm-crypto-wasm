#!/usr/bin/env bash
#
# 在 Docker 容器内从源码构建 `Cubelrti/sm-crypto-wasm`（Rust → WebAssembly），
# 产出 `--target nodejs` 的 release 产物到 `bench/.vendor/cubelrti/pkg/`，
# 供 `bench/compare-cubelrti.bench.ts` 使用。
#
# 本机**不需要**安装 Rust 工具链，只需要一个可用的 Docker 引擎与 curl。
#
# 用法：
#   bash bench/build-cubelrti-wasm.sh                        # 从 GitHub 克隆上游
#   bash bench/build-cubelrti-wasm.sh /path/to/sm-crypto-wasm # 用本地已有的克隆
#
# 环境变量：
#   SM_BUILD_IMAGE      覆盖构建镜像（默认见下）
#   WASM_PACK_VERSION   覆盖 wasm-pack 版本（默认 0.13.1）
#   SM_STRIP_LOGS=1     去掉上游每个导出函数里的 `console::log_1("invoked …")`
#                       后再构建。实测这一步对结果的影响 <3%（落在运行噪声内，
#                       同批次本库/sm-crypto-v2 的漂移还更大），默认关闭——即
#                       按上游原样构建，不篡改被测对象。
#   SM_BUILD_O3=1       改用**速度优先**配置（`opt-level = 3` + `wasm-opt = ["-O3"]`）
#                       取代上游默认的体积优先（`opt-level = "z"` + `-Oz`）。实测
#                       可让 Cubelrti 快 26%~53%（SM3 达 53%），代价是 wasm 体积从
#                       177 KB 涨到 263 KB。**默认关闭**：默认构建忠实复现上游发布配置
#                       （其仓库提交的预构建产物 175 KB 即 -Oz 版）。
#
# 三处与上游源码有关的说明：
#   1. 其 Cargo.toml 顶部用了 nightly-only 的 `cargo-features = ["trim-paths"]`
#      与 `trim-paths = "all"`，stable cargo 会直接拒绝解析整个 manifest。这两项
#      只影响二进制里的路径重映射（不改变生成代码），故在**构建副本**中剔除，
#      不动上游源码。
#   2. `SM_STRIP_LOGS` 与 `SM_BUILD_O3` 同样只改构建副本。
#   3. 构建镜像里有 binaryen，wasm-opt 会被执行（参数来自上游 Cargo.toml 的
#      `[package.metadata.wasm-pack.profile.release]`，即 `-Oz`）。
set -euo pipefail

REPO_URL="https://github.com/Cubelrti/sm-crypto-wasm.git"
WASM_PACK_VERSION="${WASM_PACK_VERSION:-0.13.1}"
# Docker Hub 的 auth 端点在部分网络下会超时，默认使用 AWS Public ECR 的官方镜像副本。
IMAGE="${SM_BUILD_IMAGE:-public.ecr.aws/docker/library/rust:1.83-slim-bookworm}"
STRIP_LOGS="${SM_STRIP_LOGS:-0}"
BUILD_O3="${SM_BUILD_O3:-0}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/bench/.vendor/cubelrti/pkg"

for bin in docker curl tar git; do
  command -v "$bin" >/dev/null || { echo "缺少依赖：$bin" >&2; exit 1; }
done

# MSYS / Git-Bash：`-v` 的宿主侧要 Windows 风格路径（用 cygpath 转换），而容器内的
# `-w /src`、`host:/src` 不能被改写成 Windows 路径。注意只能把 `MSYS_NO_PATHCONV=1`
# 加在 docker 那一条命令上：**全局 export 会让 git/curl 把 `/tmp/...` 当成
# `C:\tmp\...`**，克隆内容与后续 cp 的路径对不上，挂载进容器的 /src 会是空目录。
mnt() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

SRC="${1:-}"
if [ -n "$SRC" ]; then
  echo "== 使用本地源码：$SRC"
  cp -r "$SRC" "$WORK/src"
else
  echo "== 克隆 $REPO_URL"
  git clone --depth 1 "$REPO_URL" "$WORK/src"
fi
test -f "$WORK/src/Cargo.toml" || { echo "源码目录里没有 Cargo.toml：$WORK/src" >&2; exit 1; }

echo "== 获取 wasm-pack $WASM_PACK_VERSION（linux-musl 静态二进制，挂载进容器）"
PB="wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl"
# Windows 自带的 curl/tar 是原生程序，不认 MSYS 的 /tmp 路径，故切到 $WORK 用相对路径。
(
  cd "$WORK"
  curl -sSfL -o wp.tar.gz \
    "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/${PB}.tar.gz"
  tar -xzf wp.tar.gz
)
mkdir -p "$WORK/wp"
cp "$WORK/$PB/wasm-pack" "$WORK/wp/"
chmod +x "$WORK/wp/wasm-pack"

echo "== 容器内构建（镜像：$IMAGE，SM_STRIP_LOGS=$STRIP_LOGS，SM_BUILD_O3=$BUILD_O3）"
MSYS_NO_PATHCONV=1 docker run --rm \
  -e SM_STRIP_LOGS="$STRIP_LOGS" \
  -e SM_BUILD_O3="$BUILD_O3" \
  -v "$(mnt "$WORK/src")":/src \
  -v "$(mnt "$WORK/wp")":/opt/wp \
  -w /src "$IMAGE" bash -c '
set -eux
export PATH=/opt/wp:$PATH
wasm-pack --version
rustup target add wasm32-unknown-unknown
# 在容器内文件系统编译：挂载卷上跑 Rust 编译会因大量小文件 I/O 慢数倍。
rm -rf /build && cp -r /src /build && cd /build
sed -i "/^cargo-features = /d; /^trim-paths = /d" Cargo.toml
if [ "${SM_STRIP_LOGS:-0}" = "1" ]; then
  echo "== 去掉 console::log_1 =="
  sed -i "/console::log_1/d" src/lib.rs src/crypto/sm2.rs src/crypto/sm3.rs src/crypto/sm4.rs
fi
if [ "${SM_BUILD_O3:-0}" = "1" ]; then
  echo "== 速度优先：opt-level = 3 + wasm-opt -O3 =="
  sed -i "s/opt-level = \"z\"/opt-level = 3/" Cargo.toml
  sed -i "s/wasm-opt = \[\"-Oz\"\]/wasm-opt = [\"-O3\"]/" Cargo.toml
  grep -n "opt-level\|wasm-opt" Cargo.toml
fi
wasm-pack build --target nodejs --release
rm -rf /src/pkg && mkdir -p /src/pkg && cp -r /build/pkg/. /src/pkg/
'

echo "== 安装到 $OUT"
rm -rf "$OUT"
mkdir -p "$OUT"
cp -r "$WORK/src/pkg/." "$OUT/"
ls -la "$OUT"
echo "== 完成。运行：pnpm bench:cubelrti"
