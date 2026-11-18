#!/usr/bin/env bash
#
# TrollAppScanner 一键构建 .tipa（TrollStore 安装包）
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
ENTITLEMENTS="$ROOT/TrollAppScanner/AppScanner.entitlements"
BINARY_NAME="$TARGET"
BINARY="$PAYLOAD/$TARGET.app/$BINARY_NAME"

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
STEP=0
TOTAL=8
step() { STEP=$((STEP + 1)); echo ""; echo "==> [$STEP/$TOTAL] $1"; }
die()  { echo "${RED}!! $1${RST}" >&2; exit 1; }

echo "=============================================="
echo "  TrollAppScanner 构建"
echo "=============================================="

# ---------------------------------------------------------------- 前置检查
step "检查工具链"

command -v xcodebuild >/dev/null 2>&1 || die "找不到 xcodebuild。先装 Xcode 命令行工具：xcode-select --install"
command -v python3    >/dev/null 2>&1 || die "找不到 python3（用于生成图标）"
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
rm -rf "$BUILD_DIR" "$PAYLOAD" "$OUTPUT"
echo "    已清空 build/ Payload/ AppScanner.tipa"

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

echo "    ---- 动态库依赖 ----"
DEPS="$(otool -L "$APP/$BINARY_NAME" 2>/dev/null | tail -n +2 | awk '{print $1}')"
printf '%s\n' "$DEPS" | sed 's/^/      /'

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
done <<< "$DEPS"

if [ -n "$MISSING" ]; then
  echo "    ${YEL}警告：以下依赖在包内找不到：$MISSING${RST}"
fi

SWIFT_LIBS="$(ls "$APP/Frameworks" 2>/dev/null | wc -l | tr -d ' ')"
if [ "$SWIFT_LIBS" -gt 0 ]; then
  echo "    Frameworks 内嵌库：$SWIFT_LIBS 个"
else
  echo "    依赖系统 Swift 运行时（iOS 12.2+ 自带，正常）"
fi

# ---------------------------------------------------------------- 组装
step "组装 Payload/"
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

# ---------------------------------------------------------------- 签名
step "注入 entitlements（platform-application / no-sandbox）"
SIGNED=0
if [ "$HAVE_LDID" -eq 1 ]; then
  if ldid -S"$ENTITLEMENTS" "$BINARY"; then
    SIGNED=1
    echo "    ${GRN}ldid 签名完成${RST}"
  else
    echo "    ${YEL}ldid 执行失败${RST}"
  fi
fi

if [ "$SIGNED" -eq 0 ]; then
  [ "${TAS_ALLOW_CODESIGN_FALLBACK:-0}" = "1" ] || die "签名失败，且未允许降级。"
  echo "    改用 codesign ad-hoc 签名（entitlements 可能不生效）"
  codesign -f -s - --entitlements "$ENTITLEMENTS" "$PAYLOAD/$TARGET.app" || die "codesign 失败"
  codesign -f -s - "$BINARY" 2>/dev/null || true
fi

# 嵌套二进制（Frameworks / PlugIns）也要签一遍。
# 嵌入的 Swift 运行时 dylib 若没签名，装到设备上 dyld 会拒绝加载 —— 一样是闪退。
if [ "$HAVE_LDID" -eq 1 ]; then
  NESTED=0
  NESTED_FAIL=0
  while IFS= read -r -d '' nested; do
    case "$nested" in
      *.dylib|*/Frameworks/*)
        # dylib 用 ad-hoc 签名即可，不需要那份越权 entitlements
        if ldid -S "$nested" 2>/dev/null; then NESTED=$((NESTED + 1)); else NESTED_FAIL=$((NESTED_FAIL + 1)); fi
        ;;
      *)
        if ldid -S"$ENTITLEMENTS" "$nested" 2>/dev/null; then NESTED=$((NESTED + 1)); else NESTED_FAIL=$((NESTED_FAIL + 1)); fi
        ;;
    esac
  done < <(find "$PAYLOAD/$TARGET.app/Frameworks" "$PAYLOAD/$TARGET.app/PlugIns" -type f -print0 2>/dev/null)
  echo "    嵌套二进制已签名：$NESTED 个，失败 $NESTED_FAIL 个"
  [ "$NESTED_FAIL" -eq 0 ] || die "有 $NESTED_FAIL 个嵌套二进制签名失败，装上去会加载不了。"
fi

# 自检：entitlements 必须真的写进了二进制
echo "    ---- 二进制内实际 entitlements ----"
ENT_TEXT=""
if [ "$HAVE_LDID" -eq 1 ]; then
  ENT_TEXT="$(ldid -e "$BINARY" 2>/dev/null || true)"
fi
if [ -z "$ENT_TEXT" ]; then
  ENT_TEXT="$(codesign -d --entitlements :- "$BINARY" 2>/dev/null || true)"
fi
if [ -n "$ENT_TEXT" ]; then
  printf '%s\n' "$ENT_TEXT" | head -40
else
  echo "    ${YEL}（读取不到，可能签名格式特殊）${RST}"
fi
echo "    ----------------------------------"

if ! printf '%s' "$ENT_TEXT" | grep -q "no-sandbox"; then
  die "自检失败：二进制里没有 com.apple.private.security.no-sandbox。
    这个包装上去也扫不到任何 App，不要浪费时间。"
fi
if ! printf '%s' "$ENT_TEXT" | grep -q "platform-application"; then
  die "自检失败：二进制里没有 platform-application，读不到 /Applications。"
fi
echo "    ${GRN}自检通过：两个关键 entitlement 都在${RST}"

# ---------------------------------------------------------------- 打包
step "打包 AppScanner.tipa"
rm -f "$OUTPUT"
zip -qry "$OUTPUT" Payload -x "*.DS_Store" -x "__MACOSX/*" -x "*/._*"

unzip -l "$OUTPUT" | grep -q "Payload/$TARGET.app/$BINARY_NAME" \
  || die "打包异常：tipa 里找不到主二进制"
rm -rf "$PAYLOAD"

SIZE="$(du -h "$OUTPUT" | awk '{print $1}')"
if command -v shasum >/dev/null 2>&1; then
  SHA="$(shasum -a 256 "$OUTPUT" | awk '{print $1}')"
else
  SHA="$(sha256sum "$OUTPUT" | awk '{print $1}')"
fi

echo ""
echo "=============================================="
echo "  ${GRN}构建完成${RST}"
echo "  产物: $OUTPUT"
echo "  体积: $SIZE"
echo "  SHA256: $SHA"
echo ""
echo "  安装步骤:"
echo "    1. 把 AppScanner.tipa 传到 iPhone（AirDrop / 文件 App / 局域网）"
echo "    2. 用 TrollStore 打开 -> Install"
echo "    3. 打开 App，左上角听诊器图标进「环境诊断」"
echo "       确认 no-sandbox / platform-application 都是 OK"
echo "=============================================="
