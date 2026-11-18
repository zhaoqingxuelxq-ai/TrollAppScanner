# TrollAppScanner · 巨魔安装包扫描器

一个跑在 **TrollStore（巨魔）** 环境下的 iOS App，用来把整台设备上**所有已安装的 `.app` 安装包**扫一遍，把它们的身份、路径、体积、签名、Entitlements、注入库全部挖出来。

- 适用系统：iOS 14.0 – 16.6.1、iOS 17.0（TrollStore 支持范围）
- 界面：SwiftUI，原生
- 产物：`AppScanner.tipa`，TrollStore 直接安装

---

## 一、能扫出什么

| 项目 | 说明 |
|---|---|
| 全部安装包 | `/var/containers/Bundle/Application`（用户/侧载/TrollStore）、`/Applications`（系统）、`/System/Library/CoreServices/SystemApps` |
| 基本信息 | 显示名、Bundle ID、版本号、Build、最低系统版本 |
| 体积 | 递归统计 bundle 内所有常规文件大小 |
| 安装时间 | bundle 目录创建时间 |
| 数据容器 | 通过 `MCMMetadataIdentifier` 把 bundleID 映射到 `/var/mobile/Containers/Data/Application/<UUID>` |
| 架构 | 解析 Mach-O（含 FAT），识别 arm64 / arm64e / armv7 / x86_64 |
| 加密状态 | `LC_ENCRYPTION_INFO(_64)` 的 `cryptid` + `SC_Info` 目录 |
| 签名 | 自己解析 `LC_CODE_SIGNATURE → SuperBlob → CodeDirectory`，拿 identifier、TeamID、是否 ad-hoc、platform 标记、签名摘要 |
| Entitlements | 解析 `CSMAGIC_ENTITLEMENTS` blob，完整列出。敏感项（`platform-application`、`no-sandbox`、`get-task-allow`、`dynamic-codesigning`…）橙色高亮 |
| 注入检测 | 遍历 `LC_LOAD_DYLIB`，命中 `TweakInject` / `MobileSubstrate` / `libhooker` / `ellekit` / `/var/jb/` / `.jbroot` / Frida / Cycript 等标记的直接标红 |
| 描述文件 | 解析 `embedded.mobileprovision`：Team 名称 / TeamID、企业签还是 Ad Hoc、登记设备数、**过期时间与剩余天数** |
| 二进制元数据 | `LC_UUID`、`LC_BUILD_VERSION` 里的真实最低版本与编译 SDK（比 Info.plist 里可篡改的字段靠谱） |
| 缺失依赖 | 展开 `@rpath` / `@executable_path` / `@loader_path`，列出「链接了但文件不存在」的库 —— 这类 App 一启动就闪退 |
| 外部依赖 | 绝对路径、且不在 `/usr/lib`、`/System` 下的 dylib 单独列出（通常意味着被改过） |
| App 扩展 | 扫描 `PlugIns/*.appex` |
| URL Schemes | `CFBundleURLTypes` |
| App Groups | 从 entitlements 的 `com.apple.security.application-groups` 取 |
| 隐私权限 | 所有 `*UsageDescription` |
| 重复副本 | 同一 Bundle ID 出现多个副本时打「重复」标（TrollStore 常见） |
| 导出 | JSON / CSV（带 BOM，Excel 直接开）/ 文本报告，走系统分享面板 |

内置「环境诊断」页，能直接告诉你 `no-sandbox`、`platform-application` 有没有真的签进去、系统目录读不读得到。

---

## 二、构建（三种方式，任选一种）

### 方式 A：GitHub Actions 一键出包（**不需要 Mac**，推荐）

**Windows 也能用，全程不装 Xcode。** 三步：

**第一步：在 GitHub 网页上建个空仓库**
打开 https://github.com/new ，名字随便（例如 `trollappscanner`），Private 也可以，**不要**勾选 "Add a README file"，点 Create。

**第二步：把代码推上去**
本目录已经初始化好 git 仓库并完成了首次提交，你只需要接上远程地址：

```bash
cd TrollAppScanner
git remote add origin https://github.com/<你的用户名>/trollappscanner.git
git push -u origin main
```

第一次 push 会弹窗口要 GitHub 授权，按提示登录即可。

**第三步：拿包**
push 完之后 Actions **会自动开始构建**（不用手动点）。
打开仓库的 **Actions** 标签 → 点最新那次 `Build TrollAppScanner tipa` → 页面底部 **Artifacts** → 下载 `TrollAppScanner-tipa.zip` → 解压得到 `AppScanner.tipa`。

自动构建没触发（比如仓库默认分支叫 `master` 以外的东西），就手动来：Actions → 左侧 `Build TrollAppScanner tipa` → 右侧 **Run workflow** → 选分支 → 绿色按钮。

单次耗时约 3–6 分钟。

> **构建脚本自带三道自检，失败会直接报红，不会给你一个装不上的空包：**
> 1. `ldid` 不在就退出（codesign 降级的 entitlements 装上去无效，与其白折腾不如早报错）
> 2. 签完立刻回读二进制，`no-sandbox` / `platform-application` 少一个就退出
> 3. 打完 tipa 再解压验一遍主二进制和 entitlements
>
> 所以 **Action 绿了 = 包一定能扫出东西**；红了你把日志贴给我就行。

> **`.gitattributes` 别删。** 你在 Windows 上，git 默认会把 `build.sh` 存成 CRLF 换行，推上去 bash 直接报 `bad interpreter: /usr/bin/env: bash^M`。那个文件锁死了 sh/yml 用 LF，workflow 里也加了 `sed` 兜底。

### 方式 B：本地 Mac 构建

```bash
cd TrollAppScanner
brew install ldid          # 必需：TrollStore 只认 ldid 签名格式
chmod +x build.sh
./build.sh
# 产物：./AppScanner.tipa
```

要求：Xcode 14 及以上（命令行工具齐全即可）。

`ldid` 装不上时脚本会直接退出。真要硬着头皮用 codesign 降级（**不推荐**，entitlements 大概率不生效）：

```bash
TAS_ALLOW_CODESIGN_FALLBACK=1 ./build.sh
```

### 方式 C：用 Xcode 打开

```bash
open AppScanner.xcodeproj
```

选真机 → 编译出 `AppScanner.app`，然后手动：

```bash
mkdir -p Payload
cp -R build/Release-iphoneos/AppScanner.app Payload/
ldid -STrollAppScanner/AppScanner.entitlements Payload/AppScanner.app/AppScanner
zip -qry AppScanner.tipa Payload
```

> 注意：直接在 Xcode 里点 Run 装上去的是**普通沙盒 App**，没有 `no-sandbox`，扫描结果会是空的。必须走 ldid/codesign 注入 entitlements + TrollStore 安装这条链。

---

## 三、安装到手机

1. 把 `AppScanner.tipa` 传到 iPhone（AirDrop、文件 App、局域网、iCloud 都行）。
2. 用 **TrollStore** 打开它 → `Install`。
3. 首次启动，进左上角 **环境诊断**，确认这几行是绿色 OK：
   - `/var/containers/Bundle/Application`
   - `/Applications`
   - `com.apple.private.security.no-sandbox`
   - `platform-application`

只要 `no-sandbox` 和 `platform-application` 是 OK，扫描就是全量的。

---

## 四、为什么能读到沙盒外

TrollStore 安装时会用 `ldid` 给主二进制重新签名，**保留二进制里已有的 entitlements**。本项目在 `AppScanner.entitlements` 里预置了：

```xml
<key>platform-application</key><true/>
<key>com.apple.private.security.no-sandbox</key><true/>
<key>com.apple.private.mobileinstall.allowedSPI</key>
<array><string>Lookup</string><string>Browse</string>...</array>
```

- `platform-application` → 让进程以 platform 身份运行，可以进 `/Applications`、`/System`
- `com.apple.private.security.no-sandbox` → 彻底脱离容器沙盒，`/var/containers/Bundle/Application` 全可读
- 没有这两个，App 只能看到自己容器的几十个文件

---

## 五、目录结构

```
TrollAppScanner/
├── AppScanner.xcodeproj/
│   └── project.pbxproj            # 手写工程文件，Xcode 14+ 格式
├── TrollAppScanner/
│   ├── AppMain.swift              # @main + 主列表 + 搜索/过滤/排序 + 分享面板
│   ├── AppDetailView.swift        # 详情页 + 原始 plist + 环境诊断
│   ├── Models.swift               # AppRecord / CodeSignInfo / 格式化 / 图标缓存
│   ├── Scanner.swift              # 目录枚举 + Mach-O + CodeSignature + 容器映射
│   ├── Export.swift               # JSON / CSV / 报告导出
│   ├── Info.plist                 # 已设 60x60 图标、文件共享
│   └── AppScanner.entitlements    # 关键：越界读取权限
├── tools/make_icon.py             # 纯标准库生成 1024 图标
├── build.sh                       # 一键编译 + 签名 + 自检 + 打 tipa
├── .github/workflows/build.yml    # 云端出包
├── .gitattributes                 # 锁 LF 换行（Windows 上必须有）
├── .gitignore
└── README.md
```

---

## 六、常见问题

**Q：扫出来是空的，或者只有几个 App？**
看「环境诊断」。`no-sandbox` / `platform-application` 只要有一个是 NO，就说明签名没生效。多半是没用 TrollStore 装，或者手动改过包。重新用 TrollStore 装原始 tipa。

**Q：为什么有些系统 App 没有图标？**
系统 App 的图标在 `Assets.car` 里，没走 `CFBundleIconFiles` 的会读不到，会显示占位图标，不影响其他数据。

**Q：扫描很慢？**
首次要递归统计每个 bundle 的体积（系统 App 加起来好几 GB），几十秒正常。进度条会实时显示当前在扫哪个包。

**Q：`重复` 标是什么意思？**
同一个 Bundle ID 在设备上存在多个副本（TrollStore 装了两份、或系统 App 被侧载版覆盖过）。点进去看路径就能区分。

**Q：`注入` 标是什么意思？**
这个 App 的主二进制里链接了 tweak 注入库（TrollFools、TrollStore 注入、越狱环境残留）。列表里红色高亮，详情页会列出每一个 dylib 路径。

**Q：能卸载 App 吗？**
本工具只做扫描和导出，不碰任何写入。想卸载请用 TrollStore 本身。

**Q：企业签的 App 打开就闪退，用这个能看出原因吗？**
两个最常见原因都能看到：一是列表里出现「已过期」标签、详情页「有效期至」标红 —— 证书废了；二是标签「缺依赖」，详情页会列出具体是哪个 dylib 找不到文件 —— 通常是 TrollStore 卸载 tweak 后残留的注入引用。两种情况分开处理。

**Q：`签名摘要` 是什么？**
CodeDirectory 的 SHA-256 前 24 位。同一份二进制重新 ldid 签名后这个值会变，可以用来判断「这个包是不是被人重签过」。

---

## 八、更新记录

**1.1.0**
- 新增描述文件解析（Team、企业签/Ad Hoc、设备数、过期时间），列表增加「已过期」筛选
- 新增 `LC_UUID` / 编译 SDK / 二进制真实最低版本
- 新增缺失依赖检测（@rpath 展开）
- 注入检测覆盖 App 扩展与 Frameworks 内部（原来只看主二进制）
- 修复：注入库匹配用宽泛子串（`applist`、`flex`）导致正常 App 误标红
- 修复：`AppDetailView` 的 List 超过 10 个顶层视图，ViewBuilder 编译报错
- 修复：进度回调重复派发导致状态文字滞后
- 构建：`build.sh` 增加三道自检，ldid 缺失直接失败而不是静默降级

**1.0.0**
- 首发

---

## 七、免责声明

本项目只做**读取**：遍历目录、读 plist、读 Mach-O、读代码签名，全程不写入、不修改、不删除任何第三方 App 的任何文件。导出文件写在 App 自己的临时目录里，再通过系统分享面板交给你。
