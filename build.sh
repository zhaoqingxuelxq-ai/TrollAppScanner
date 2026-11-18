#!/usr/bin/env bash
#
# TrollAppScanner 一键构建 .tipa（TrollStore 安装包）
#
# 一次编译，产出两个包：
#   AppScanner.tipa        主程序
#   AppScanner-Probe.tipa  启动探针（同二进制，只改 Info.plist）
#
# 用法：
#   ./build.sh                                 # 正常构建
#   TAS_ALLOW_CODESIGN_FALLBACK=1 ./build.sh   # ldid 不可用时允许降级（不推荐）
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PROJECT="AppScanner.xcodeproj"
TARGET="AppScanner"
BUILD_DIR="$ROOT/build"
PAYLOAD="$ROOT/Payload"
OUTPUT="$ROOT/AppScanner.tipa"
PROBE_ROOT="$ROOT/probe"
PROBE_PAYLOAD="$PROBE_ROOT/Payload"
PROBE_APP="$PROBE_PAYLOAD/AppScannerProbe.app"
OUTPUT_PROBE="$ROOT/AppScanner-Probe.tipa"
ENTITLEMENTS="$ROOT/TrollAppScanner/AppScanner.entitlements"
BINARY_NAME="$TARGET"
BINARY="$PAYLOAD/$TARGET.app/$BINARY_NAME"

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
STEP=0
TOTAL=10
step() { STEP=$((STEP + 1)); echo ""; echo "==> [$STEP/$TOTAL] $1"; }
die()  { echo "${RED}!! $1${RST}" >&2; exit 1; }

echo "=============================================="
echo "  TrollAppScanner 构建"
echo "=============================================="

# ---------------------------------------------------------------- 前置检查
step "检查工具链"

command -v xcodebuild >/dev/null 2>&1 || die "找不到 xcodebuild。先装 Xcode 命令行工具：xcode-select --install"
command -v python3    >/dev/null 2>&1 || die "找不到 python3（用于生成图标 / 改 Info.plist）"
command -v zip        >/dev/null 2>&1 || die "找不到 zip（macOS 自带，异常）"
[ -f "$ENTITLEMENTS" ] || die "找不到 entitlements 文件：$ENTITLEMENTS"

echo "    Xcode: $(xcodebuild -version 2>/dev/null | head -1)"
SDK_VER="$(xcrun --sdk iphoneos --show-sdk-version 2>/dev/null || echo unknown)"
echo "    SDK  : $SDK_VER"

# iOS 26 SDK（Xcode 26）编出来的二进制跑在 iOS 14~18 上会在 dyld 阶段
# 报 Symbol not found 直接闪退，这是实测踩过的坑，必须挡在前面。
if [ "$SDK_VER" != "unknown" ]; then
  SDK_MAJOR="${SDK_VER%%.*}"
  if [ "$SDK_MAJOR" -gt 18 ]; then
    die "iOS SDK $SDK_VER 过新（>18）。用新 SDK 编面向 iOS 14 的包，装到老系统必然闪退。
    换 Xcode 16.x：  sudo xcode-select -s /Applications/Xcode_16.4.app"
  fi
fi

HAVE_LDID=0
if command -v ldid >/dev/null 2>&1; then
  HAVE_LDID=1
  echo "    ldid : $(command -v ldid)"
else
  echo "    ldid : ${YEL}未安装${RST}"
  if [ "${TAS_ALLOW_CODESIGN_FALLBACK:-0}" != "1" ]; then
    die "缺少 ldid。TrollStore 依赖 ldid 签名格式，codesign 降级后 entitlements 通常不生效。
    装一下再来：  brew install ldid
    仍要继续：    TAS_ALLOW_CODESIGN_FALLBACK=1 ./build.sh"
  fi
  echo "    ${YEL}已按 TAS_ALLOW_CODESIGN_FALLBACK=1 允许降级${RST}"
fi

# ---------------------------------------------------------------- 清理
step "清理旧产物"
rm -rf "$BUILD_DIR" "$PAYLOAD" "$PROBE_ROOT" "$OUTPUT" "$OUTPUT_PROBE"
echo "    已清空 build/ Payload/ probe/ 与两个 .tipa"

# ---------------------------------------------------------------- 编译
step "编译（iphoneos / arm64 / Release / 不签名）"
xcodebuild \
  -project "$PROJECT" \
  -target "$TARGET" \
  -sdk iphoneos \
  -configuration Release \
  ARCHS=arm64 \
  ONLY_ACTIVE_ARCH=NO \
  ALWAYS_EMBED_SWIFT_STANDARD_LIBRARIES=NO \
  SWIFT_OPTIMIZATION_LEVEL="-O" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGN_IDENTITY="" \
  CONFIGURATION_BUILD_DIR="$BUILD_DIR" \
  build 2>&1 | tail -30

APP="$BUILD_DIR/$TARGET.app"
[ -d "$APP" ] || die "编译产物不存在：$APP"
[ -f "$APP/$BINARY_NAME" ] || die "可执行文件不存在：$APP/$BINARY_NAME"
echo "    产物: $APP"

# ---------------------------------------------------------------- 依赖体检
step "检查二进制依赖"
echo "    ---- 编译 SDK / 最低系统 ----"
otool -l "$APP/$BINARY_NAME" 2>/dev/null | grep -A5 "LC_BUILD_VERSION" | head -8 || true

# 关键护栏：minos 必须 <= 16.0，否则 iOS 16.3.1 根本装不上/起不来。
MINOS="$(otool -l "$APP/$BINARY_NAME" 2>/dev/null | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $2; exit}')"
if [ -n "$MINOS" ]; then
  MINOS_MAJOR="${MINOS%%.*}"
  echo "    minos = $MINOS"
  if [ "$MINOS_MAJOR" -gt 16 ]; then
    die "最低系统版本被编成了 iOS $MINOS，高于 iOS 16.3.1，装上去必然闪退。
    检查 project.pbxproj 里的 IPHONEOS_DEPLOYMENT_TARGET。"
  fi
else
  echo "    ${YEL}（读不到 minos，跳过校验）${RST}"
fi

echo "    ---- 动态库依赖 ----"
DEPS=""
if [ -f "$APP/$BINARY_NAME" ]; then
  DEPS="$(otool -L "$APP/$BINARY_NAME" 2>/dev/null | tail -n +2 | awk 'NF{print $1}')" || DEPS=""
fi
if [ -n "$DEPS" ]; then
  printf '%s\n' "$DEPS" | sed 's/^/      /'
else
  echo "      （读取失败）"
fi

# @rpath / @executable_path 形式的依赖必须能在包里找到，否则设备上 dyld 直接拒载
MISSING=""
while IFS= read -r dep; do
  [ -n "$dep" ] || continue
  case "$dep" in
    @rpath/*)
      base="${dep#@rpath/}"
      [ -f "$APP/Frameworks/$base" ] || MISSING="$MISSING $dep"
      ;;
    @executable_path/*)
      base="${dep#@executable_path/}"
      [ -f "$APP/$base" ] || MISSING="$MISSING $dep"
      ;;
  esac
done <<< "$DEPS" || true

if [ -n "$MISSING" ]; then
  echo "    ${YEL}警告：以下依赖在包内找不到：$MISSING${RST}"
fi

# 注意：pipefail 下 ls 一个不存在的目录会让整个管道返回非零，进而被 set -e 杀掉。
SWIFT_LIBS=0
if [ -d "$APP/Frameworks" ]; then
  SWIFT_LIBS="$(ls "$APP/Frameworks" 2>/dev/null | wc -l | tr -d ' ')"
fi
if [ "${SWIFT_LIBS:-0}" -gt 0 ]; then
  echo "    Frameworks 内嵌库：$SWIFT_LIBS 个"
else
  echo "    依赖系统 Swift 运行时（iOS 12.2+ 自带，正常）"
fi

# ---------------------------------------------------------------- 组装主包
step "组装主包 Payload/AppScanner.app"
mkdir -p "$PAYLOAD"
cp -R "$APP" "$PAYLOAD/"

# ---------------------------------------------------------------- 图标
step "生成并注入图标"
python3 "$ROOT/tools/make_icon.py" "$ROOT/icon-1024.png" >/dev/null
for spec in "120 AppIcon60x60@2x.png" "180 AppIcon60x60@3x.png"; do
  size="${spec%% *}"; name="${spec##* }"
  sips -z "$size" "$size" "$ROOT/icon-1024.png" --out "$PAYLOAD/$TARGET.app/$name" >/dev/null
done
echo "    已写入 AppIcon60x60@2x.png / AppIcon60x60@3x.png"

# ---------------------------------------------------------------- 探针包
step "派生探针包（同一个二进制，只改 Info.plist）"
mkdir -p "$PROBE_PAYLOAD"
cp -R "$PAYLOAD/$TARGET.app" "$PROBE_APP"
python3 - "$PROBE_APP/Info.plist" <<'PY'
import sys, plistlib
path = sys.argv[1]
with open(path, 'rb') as f:
    info = plistlib.load(f)
info['CFBundleIdentifier']       = 'com.troll.appscanner.probe'
info['CFBundleDisplayName']      = '扫描探针'
info['CFBundleName']             = 'AppScannerProbe'
info['TASProbe']                 = True
with open(path, 'wb') as f:
    plistlib.dump(info, f, fmt=plistlib.FMT_BINARY)
print('    bundle id -> com.troll.appscanner.probe，TASProbe=true')
PY
echo "    探针包: $PROBE_APP"

# ---------------------------------------------------------------- 签名
step "签名（ldid + entitlements）"

sign_bundle() {
  local appdir="$1"
  local bin="$appdir/$BINARY_NAME"

  if [ "$HAVE_LDID" -eq 1 ]; then
    ldid -S"$ENTITLEMENTS" "$bin" || return 1

    # 嵌套二进制（Frameworks / PlugIns）也要签，否则 dyld 会拒绝加载。
    local nested=0
    local failed=0
    while IFS= read -r -d '' item; do
      case "$item" in
        *.dylib)
          if ldid -S "$item" 2>/dev/null; then nested=$((nested + 1)); else failed=$((failed + 1)); fi
          ;;
        *)
          if ldid -S"$ENTITLEMENTS" "$item" 2>/dev/null; then nested=$((nested + 1)); else failed=$((failed + 1)); fi
          ;;
      esac
    done < <(find "$appdir/Frameworks" "$appdir/PlugIns" -type f -print0 2>/dev/null)

    if [ "$nested" -gt 0 ]; then
      echo "    嵌套二进制已签名：$nested 个"
    fi
    if [ "$failed" -ne 0 ]; then
      echo "    ${RED}嵌套签名失败：$failed 个${RST}"
      return 1
    fi
    return 0
  fi

  [ "${TAS_ALLOW_CODESIGN_FALLBACK:-0}" = "1" ] || return 1
  codesign -f -s - --entitlements "$ENTITLEMENTS" "$appdir" || return 1
  codesign -f -s - "$bin" 2>/dev/null || true
  return 0
}

echo "    ---- 主包 ----"
sign_bundle "$PAYLOAD/$TARGET.app" || die "主包签名失败。装上去会加载不了。"
echo "    ${GRN}主包签名完成${RST}"

echo "    ---- 探针包 ----"
sign_bundle "$PROBE_APP" || die "探针包签名失败。"
echo "    ${GRN}探针包签名完成${RST}"

# ---------------------------------------------------------------- 自检
step "自检 entitlements"

verify_bundle() {
  local label="$1"
  local appdir="$2"
  local bin="$appdir/$BINARY_NAME"
  local text=""

  if [ "$HAVE_LDID" -eq 1 ]; then
    text="$(ldid -e "$bin" 2>/dev/null || true)"
  fi
  if [ -z "$text" ]; then
    text="$(codesign -d --entitlements :- "$bin" 2>/dev/null || true)"
  fi

  if ! printf '%s' "$text" | grep -q "no-sandbox"; then
    echo "    ${RED}$label 缺 com.apple.private.security.no-sandbox（扫不到任何 App）${RST}"
    return 1
  fi
  if ! printf '%s' "$text" | grep -q "platform-application"; then
    echo "    ${RED}$label 缺 platform-application（读不到 /Applications）${RST}"
    return 1
  fi
  # get-task-allow 是 TrollStore 上的头号杀手：调试类 entitlement 没有合法证书链
  # 背书时，AMFI 会在 exec 阶段直接杀进程 —— 白屏闪退。
  if printf '%s' "$text" | grep -q "get-task-allow"; then
    echo "    ${RED}$label 里还有 get-task-allow，装上去必定闪退${RST}"
    return 1
  fi

  echo "    ${GRN}$label 通过（no-sandbox + platform-application，无 get-task-allow）${RST}"
  return 0
}

verify_bundle "主包"   "$PAYLOAD/$TARGET.app" || die "自检不通过，不要装。"
verify_bundle "探针包" "$PROBE_APP"           || die "自检不通过，不要装。"

echo "    ---- 主包 entitlements 实际内容 ----"
if [ "$HAVE_LDID" -eq 1 ]; then
  ldid -e "$BINARY" 2>/dev/null | head -30 || true
fi
echo "    ------------------------------------"

# ---------------------------------------------------------------- 打包
step "打包两个 .tipa"
(cd "$ROOT" && zip -qry "$OUTPUT" Payload -x "*.DS_Store" -x "__MACOSX/*" -x "*/._*")
(cd "$PROBE_ROOT" && zip -qry "$OUTPUT_PROBE" Payload -x "*.DS_Store" -x "__MACOSX/*" -x "*/._*")

unzip -l "$OUTPUT" | grep -q "Payload/$TARGET.app/$BINARY_NAME" \
  || die "打包异常：主包里找不到主二进制"
unzip -l "$OUTPUT_PROBE" | grep -q "Payload/AppScannerProbe.app/$BINARY_NAME" \
  || die "打包异常：探针包里找不到主二进制"

rm -rf "$PAYLOAD" "$PROBE_ROOT"

SIZE="$(du -h "$OUTPUT" | awk '{print $1}')"
SIZE_P="$(du -h "$OUTPUT_PROBE" | awk '{print $1}')"
if command -v shasum >/dev/null 2>&1; then
  SHA="$(shasum -a 256 "$OUTPUT" | awk '{print $1}')"
  SHA_P="$(shasum -a 256 "$OUTPUT_PROBE" | awk '{print $1}')"
else
  SHA="$(sha256sum "$OUTPUT" | awk '{print $1}')"
  SHA_P="$(sha256sum "$OUTPUT_PROBE" | awk '{print $1}')"
fi

echo ""
echo "=============================================="
echo "  ${GRN}构建完成${RST}"
echo ""
echo "  主包:   $OUTPUT  ($SIZE)"
echo "  SHA256: $SHA"
echo ""
echo "  探针包: $OUTPUT_PROBE  ($SIZE_P)"
echo "  SHA256: $SHA_P"
echo ""
echo "  装哪个:"
echo "    先装 AppScanner-Probe.tipa。它能打开并显示「启动探针」页，"
echo "    就说明签名 / 安装 / 系统加载全链路 OK，再装主包。"
echo "    如果探针包也白屏闪退，问题在打包签名，不在代码，改代码没用。"
echo "=============================================="
