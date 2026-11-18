//
//  AppMain.swift
//  TrollAppScanner
//
//  程序入口 + 主列表界面
//

import SwiftUI
import UIKit

// MARK: - 程序入口
//
// 为什么不用 SwiftUI 的 @main App + WindowGroup
// ---------------------------------------------------------------
// 1.0 ~ 1.2 三个版本都用 @main struct: App，结果在 iOS 16.3.1 + TrollStore 上全部
// 「点图标 → 白屏 → 闪退」，界面里一个字都看不到。改代码内容（自动扫描 → 手动扫描）
// 没有任何变化，说明问题不在业务逻辑，而在更靠前的启动链路。
//
// 现在换回最原始的 UIApplicationDelegate + 手写 UIWindow：
//   1. 不依赖 UIApplicationSceneManifest。有 manifest 时，AppDelegate 里自建的
//      window 是不会被显示的（iOS 13 起 scene 接管），正好是白屏的表现。
//   2. 不依赖 SwiftUI 的 App / Scene 生命周期，SwiftUI 只当一个普通 View，
//      用 UIHostingController 塞进 window，出问题也不会连累启动。
//   3. main() 第一行就落盘日志，能把「根本没进 Swift 代码」和「进了之后才崩」分开。

// 顶层函数：作为 C 函数指针交给 NSSetUncaughtExceptionHandler。
// 写成闭包会因为「捕获上下文」而无法转换成 C 函数指针（编译期就报错）。
private func tasUncaughtExceptionHandler(_ exception: NSException) {
    let stack = exception.callStackSymbols.joined(separator: "\n")
    Boot.log("!! NSException \(exception.name.rawValue): \(exception.reason ?? "-")\n\(stack)")
}

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?

    static func main() {
        // 这一行能写出来，就说明：dyld 已加载完、签名校验已通过、进程活着、
        // Swift 运行时正常拉起。如果设备上连这行日志都没有，问题一定在
        // 签名 / 打包 / 安装环节，改再多代码也没用。
        Boot.log("0) main() 进入 · iOS \(UIDevice.current.systemVersion) · \(UIDevice.current.model)")
        Boot.log("   bundle = \(Bundle.main.bundlePath)")
        Boot.log("   exe    = \(Bundle.main.executablePath ?? "-")")

        // NSException 能在这里截住并落盘；SIGSEGV / EXC_BAD_ACCESS 截不住，
        // 但至少能把 ObjC 层的异常原因留下来。
        // 注意：NSSetUncaughtExceptionHandler 要的是 C 函数指针，不能传捕获上下文的闭包，
        // 所以这里用顶层函数 tasUncaughtExceptionHandler。
        NSSetUncaughtExceptionHandler(tasUncaughtExceptionHandler)

        // principalClass 传 nil 表示用 UIApplication 本体，delegate 用本类。
        // 前提是 Info.plist 里没有 UIApplicationSceneManifest，否则 legacy
        // 路径下自建的 window 不会显示。
        UIApplicationMain(CommandLine.argc,
                          CommandLine.unsafeArgv,
                          nil,
                          NSStringFromClass(AppDelegate.self))
    }
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        Boot.log("1) didFinishLaunching 到达")

        let window = UIWindow(frame: UIScreen.main.bounds)

        // Info.plist 里带 TASProbe=true 的包走探针界面。
        // 探针界面是纯 UIKit 手写的，不碰 SwiftUI、不碰扫描逻辑，
        // 用来单独验证「签名 → 安装 → dyld → UIKit」这条链路。
        if Bundle.main.object(forInfoDictionaryKey: "TASProbe") as? Bool == true {
            Boot.log("   探针模式（TASProbe=true）")
            window.rootViewController = UINavigationController(rootViewController: ProbeViewController())
        } else {
            window.rootViewController = UIHostingController(rootView: ContentView())
        }

        window.makeKeyAndVisible()
        self.window = window
        Boot.log("2) 根视图已挂载，window 可见")
        return true
    }
}

// MARK: - 视图模型

final class ScannerModel: ObservableObject {
    @Published var apps: [AppRecord] = []
    @Published var isScanning: Bool = false
    @Published var progress: Double = 0
    @Published var status: String = "准备扫描"
    @Published var hasScanned: Bool = false
    @Published var environment = EnvironmentInfo()

    func start() {
        guard !isScanning else { return }
        isScanning = true
        hasScanned = false
        progress = 0
        status = "开始扫描…"
        Boot.log("3) 扫描开始")

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            // 注意：AppScannerEngine 的进度回调已经内部派发到主线程，
            // 这里不能再包一层 main.async，否则文字滞后、进度条会回跳
            let result = AppScannerEngine.scan(options: ScanOptions()) { value, text in
                self.progress = value
                self.status = text
            }
            Boot.log("4) 扫描结束，共 \(result.count) 个包")
            DispatchQueue.main.async {
                self.apps = result
                Boot.log("5) 环境探测开始")
                self.environment = EnvironmentProbe.probe()
                Boot.log("6) 环境探测完成，界面更新")
                self.isScanning = false
                self.hasScanned = true
            }
        }
    }
}

// MARK: - 过滤 / 排序

enum FilterMode: String, CaseIterable, Identifiable {
    case all = "全部"
    case user = "用户"
    case system = "系统"
    case injected = "注入"
    case sideloaded = "侧载"
    case duplicate = "重复"
    case expired = "过期"

    var id: String { rawValue }
}

enum SortMode: String, CaseIterable, Identifiable {
    case size = "体积"
    case name = "名称"
    case version = "版本"
    case date = "时间"

    var id: String { rawValue }
}

// MARK: - 主界面

struct ContentView: View {

    @StateObject private var model = ScannerModel()
    @State private var query: String = ""
    @State private var filter: FilterMode = .all
    @State private var sort: SortMode = .size
    @State private var shareItems: [Any] = []
    @State private var showShare: Bool = false
    @State private var showDiagnostics: Bool = false

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                statusBar
                permissionBanner
                searchBar
                filterBar

                if model.apps.isEmpty {
                    emptyView
                } else {
                    appList
                }

                footerBar
            }
            .navigationTitle("安装包扫描")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        showDiagnostics = true
                    } label: {
                        Image(systemName: "stethoscope")
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button {
                            model.start()
                        } label: {
                            Label("重新扫描", systemImage: "arrow.clockwise")
                        }
                        Divider()
                        Button {
                            export(.json)
                        } label: {
                            Label("导出 JSON", systemImage: "curlybraces")
                        }
                        Button {
                            export(.csv)
                        } label: {
                            Label("导出 CSV", systemImage: "tablecells")
                        }
                        Button {
                            export(.report)
                        } label: {
                            Label("导出文本报告", systemImage: "doc.plaintext")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .sheet(isPresented: $showShare) {
                ShareSheet(items: shareItems)
            }
            .sheet(isPresented: $showDiagnostics) {
                DiagnosticsView()
            }
            .onAppear {
                Boot.log("2) ContentView.onAppear（界面构建完成，没有崩）")
                // 不在启动时自动全盘扫描。
                // 一进 App 就解析几百个安装包的 Mach-O 和签名，一旦某个文件畸形就整进程崩溃，
                // 表现为白屏闪退。改成用户主动点按钮，既能定位问题，也不会一打开就卡。
            }
        }
        .navigationViewStyle(StackNavigationViewStyle())
    }

    // MARK: 计算属性

    private var filteredApps: [AppRecord] {
        var list = model.apps

        switch filter {
        case .all:
            break
        case .user:
            list = list.filter { $0.kind == .user }
        case .system:
            list = list.filter { $0.kind == .system }
        case .injected:
            list = list.filter { !$0.injectedLibs.isEmpty }
        case .sideloaded:
            list = list.filter { $0.origin.contains("TrollStore") || $0.origin.contains("签名") }
        case .duplicate:
            list = list.filter { $0.isDuplicate }
        case .expired:
            list = list.filter { $0.provision.exists && $0.provision.isExpired }
        }

        let keyword = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !keyword.isEmpty {
            list = list.filter {
                $0.name.lowercased().contains(keyword)
                    || $0.bundleID.lowercased().contains(keyword)
                    || $0.bundlePath.lowercased().contains(keyword)
            }
        }

        switch sort {
        case .size:
            list.sort { $0.sizeBytes > $1.sizeBytes }
        case .name:
            list.sort { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        case .version:
            list.sort { $0.version.compare($1.version, options: .numeric) == .orderedDescending }
        case .date:
            list.sort { ($0.installDate ?? Date.distantPast) > ($1.installDate ?? Date.distantPast) }
        }
        return list
    }

    private var totalSize: Int64 {
        model.apps.reduce(Int64(0)) { $0 + $1.sizeBytes }
    }

    private func countFor(_ mode: FilterMode) -> Int {
        switch mode {
        case .all: return model.apps.count
        case .user: return model.apps.filter { $0.kind == .user }.count
        case .system: return model.apps.filter { $0.kind == .system }.count
        case .injected: return model.apps.filter { !$0.injectedLibs.isEmpty }.count
        case .sideloaded: return model.apps.filter { $0.origin.contains("TrollStore") || $0.origin.contains("签名") }.count
        case .duplicate: return model.apps.filter { $0.isDuplicate }.count
        case .expired: return model.apps.filter { $0.provision.exists && $0.provision.isExpired }.count
        }
    }

    // MARK: 子视图

    @ViewBuilder
    private var statusBar: some View {
        if model.isScanning {
            VStack(spacing: 5) {
                ProgressView(value: model.progress)
                    .progressViewStyle(LinearProgressViewStyle(tint: Color.accentColor))
                HStack(spacing: 8) {
                    Text(model.status)
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                    Spacer(minLength: 4)
                    Text("\(Int(model.progress * 100))%")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.secondary)
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 8)
        }
    }

    @ViewBuilder
    private var permissionBanner: some View {
        if model.hasScanned && !model.environment.canReadBundleRoot {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.orange)
                    .font(.system(size: 13))
                Text("没有越界读取权限，只能看到沙盒内内容。请确认使用 TrollStore 安装本 tipa。")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(10)
            .background(Color.orange.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .padding(.horizontal, 14)
            .padding(.top, 8)
        }
    }

    private var searchBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 14))
                .foregroundColor(.secondary)
            TextField("搜索名称 / Bundle ID / 路径", text: $query)
                .font(.system(size: 14))
                .autocapitalization(.none)
                .disableAutocorrection(true)
            if !query.isEmpty {
                Button {
                    query = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(PlainButtonStyle())
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(Color(UIColor.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .padding(.horizontal, 14)
        .padding(.top, 8)
    }

    private var filterBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(FilterMode.allCases) { mode in
                    FilterChip(title: mode.rawValue,
                               count: countFor(mode),
                               selected: filter == mode) {
                        filter = mode
                    }
                }

                Menu {
                    ForEach(SortMode.allCases) { mode in
                        Button {
                            sort = mode
                        } label: {
                            HStack {
                                Text(mode.rawValue)
                                if sort == mode { Image(systemName: "checkmark") }
                            }
                        }
                    }
                } label: {
                    HStack(spacing: 3) {
                        Image(systemName: "arrow.up.arrow.down")
                            .font(.system(size: 10, weight: .semibold))
                        Text(sort.rawValue)
                            .font(.system(size: 12, weight: .medium))
                    }
                    .foregroundColor(.primary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(Color(UIColor.secondarySystemBackground))
                    .clipShape(Capsule())
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
        }
    }

    private var appList: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                ForEach(filteredApps) { app in
                    NavigationLink(destination: AppDetailView(app: app)) {
                        AppRow(app: app)
                    }
                    .buttonStyle(PlainButtonStyle())

                    Divider()
                        .padding(.leading, 66)
                }
            }
        }
    }

    private var emptyView: some View {
        VStack(spacing: 14) {
            Spacer()
            Image(systemName: model.isScanning ? "hourglass" : "shippingbox")
                .font(.system(size: 52, weight: .thin))
                .foregroundColor(Color(UIColor.tertiaryLabel))
            Text(model.isScanning ? "正在扫描…" : "尚未扫描")
                .font(.system(size: 15, weight: .medium))
                .foregroundColor(.secondary)
            if !model.isScanning {
                Text(model.hasScanned
                     ? "没有找到安装包。点左上角听诊器看环境诊断，\n确认 no-sandbox 与 platform-application 是否生效。"
                     : "点下面按钮开始扫描整机安装包。\n扫描需要读取全盘文件，只在点按钮时执行。")
                    .font(.system(size: 12))
                    .foregroundColor(Color(UIColor.tertiaryLabel))
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                Button {
                    model.start()
                } label: {
                    Text(model.hasScanned ? "重新扫描" : "开始扫描")
                        .font(.system(size: 14, weight: .semibold))
                        .padding(.horizontal, 22)
                        .padding(.vertical, 10)
                        .background(Color.accentColor)
                        .foregroundColor(.white)
                        .clipShape(Capsule())
                }
                .buttonStyle(PlainButtonStyle())
            }
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var footerBar: some View {
        HStack {
            Text("\(filteredApps.count) / \(model.apps.count) 个")
            Spacer()
            Text("合计 \(humanSize(totalSize))")
        }
        .font(.system(size: 11))
        .foregroundColor(.secondary)
        .padding(.horizontal, 16)
        .padding(.vertical, 7)
        .background(Color(UIColor.systemBackground))
        .overlay(
            Rectangle()
                .fill(Color(UIColor.separator))
                .frame(height: 0.5),
            alignment: .top
        )
    }

    // MARK: 导出

    private func export(_ format: ExportFormat) {
        guard !model.apps.isEmpty else { return }
        if let url = Exporter.write(apps: model.apps, format: format) {
            shareItems = [url]
            showShare = true
        }
    }
}

// MARK: - 列表行

struct AppRow: View {
    let app: AppRecord

    var body: some View {
        HStack(spacing: 12) {
            iconView

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 5) {
                    Text(app.name)
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundColor(.primary)
                        .lineLimit(1)

                    if app.isDuplicate {
                        TagView(text: "重复", color: .orange)
                    }
                    if !app.injectedLibs.isEmpty {
                        TagView(text: "注入", color: .red)
                    }
                    if !app.missingLibs.isEmpty {
                        TagView(text: "缺依赖", color: .red)
                    }
                    if app.encrypted {
                        TagView(text: "加密", color: .blue)
                    }
                    if app.provision.exists && app.provision.isExpired {
                        TagView(text: "已过期", color: .gray)
                    }
                }

                Text(app.bundleID)
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)

                Text(app.summaryLine)
                    .font(.system(size: 10.5))
                    .foregroundColor(Color(UIColor.tertiaryLabel))
                    .lineLimit(1)
            }

            Spacer(minLength: 4)

            Image(systemName: "chevron.right")
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(Color(UIColor.tertiaryLabel))
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 9)
        .contentShape(Rectangle())
    }

    @ViewBuilder
    private var iconView: some View {
        if let image = IconCache.shared.image(at: app.iconPath) {
            Image(uiImage: image)
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 40, height: 40)
                .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
        } else {
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(Color(UIColor.secondarySystemBackground))
                .frame(width: 40, height: 40)
                .overlay(
                    Image(systemName: app.kind == .system ? "gearshape" : "shippingbox")
                        .font(.system(size: 16))
                        .foregroundColor(.secondary)
                )
        }
    }
}

// MARK: - 小组件

struct TagView: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.system(size: 9, weight: .bold))
            .foregroundColor(color)
            .lineLimit(1)
            .padding(.horizontal, 5)
            .padding(.vertical, 1.5)
            .background(color.opacity(0.15))
            .clipShape(RoundedRectangle(cornerRadius: 4, style: .continuous))
    }
}

struct FilterChip: View {
    let title: String
    let count: Int
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                Text(title)
                    .font(.system(size: 12, weight: selected ? .semibold : .regular))
                if count > 0 {
                    Text("\(count)")
                        .font(.system(size: 10, weight: .semibold))
                        .opacity(0.8)
                }
            }
            .foregroundColor(selected ? .white : .primary)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(selected ? Color.accentColor : Color(UIColor.secondarySystemBackground))
            .clipShape(Capsule())
        }
        .buttonStyle(PlainButtonStyle())
    }
}

// MARK: - 分享面板

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

// MARK: - 启动探针（纯 UIKit）
//
// 这个界面存在的唯一目的：把「哪一环坏了」这件事一次性问清楚。
//
//   它能把内容画出来  → 签名、安装、dyld、UIKit 全链路 OK。之后若主界面还闪退，
//                       就只可能是业务代码，改代码才有意义。
//   它也白屏闪退      → 问题 100% 在打包 / 签名 / 安装环节，改代码是白费力气。
//
// 所以这里刻意不 import 任何业务视图、不读全盘、不碰 SwiftUI。

final class ProbeViewController: UIViewController {

    private let scrollView = UIScrollView()
    private let stack = UIStackView()

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "启动探针"
        view.backgroundColor = .systemBackground
        buildLayout()
        render()
        Boot.log("3) 探针界面渲染完成（能看到本页说明启动链路正常）")
    }

    private func buildLayout() {
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        stack.translatesAutoresizingMaskIntoConstraints = false
        stack.axis = .vertical
        stack.spacing = 9
        stack.alignment = .fill

        view.addSubview(scrollView)
        scrollView.addSubview(stack)

        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            stack.topAnchor.constraint(equalTo: scrollView.contentLayoutGuide.topAnchor, constant: 16),
            stack.leadingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.trailingAnchor, constant: -16),
            stack.bottomAnchor.constraint(equalTo: scrollView.contentLayoutGuide.bottomAnchor, constant: -28),
            stack.widthAnchor.constraint(equalTo: scrollView.frameLayoutGuide.widthAnchor, constant: -32)
        ])
    }

    // MARK: 渲染
    //
    // 刻意不调用 EnvironmentProbe / MachO / CodeSign 里任何解析代码。
    // 探针页要和业务代码完全隔离，否则「探针自己崩了」会被误判成「链路有问题」。
    // 用不用得上 entitlements，看能不能读 /Applications 就够了。

    private func render() {
        let fm = FileManager.default

        addTitle("链路已通")
        addNote("能看到这一页，说明「签名 → TrollStore 安装 → dyld → UIKit」全部通过。"
                + "主界面如果还闪退，问题就在业务代码，不在打包。")

        addTitle("设备")
        addRow("系统版本", "iOS " + UIDevice.current.systemVersion)
        addRow("设备型号", UIDevice.current.model)
        addRow("运行 uid", "\(getuid())" + (getuid() == 501 ? "（mobile）" : ""))
        addRow("App 版本", (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "-")
        addRow("bundle id", Bundle.main.bundleIdentifier ?? "-")
        addRow("App 路径", Bundle.main.bundlePath, mono: true)

        addTitle("越界读取能力")
        addStatus("/Applications", (try? fm.contentsOfDirectory(atPath: "/Applications")) != nil)
        addStatus("/var/containers/Bundle/Application",
                  (try? fm.contentsOfDirectory(atPath: "/var/containers/Bundle/Application")) != nil)
        addStatus("/var/mobile/Containers/Data/Application",
                  (try? fm.contentsOfDirectory(atPath: "/var/mobile/Containers/Data/Application")) != nil)
        addNote("三项全 NO，说明 no-sandbox 没生效，主程序扫不到任何东西。")

        addTitle("启动日志")
        addRow("路径", Boot.docPath, mono: true)
        addNote(readBootTail())
    }

    private func readBootTail() -> String {
        guard let text = try? String(contentsOfFile: Boot.docPath, encoding: .utf8),
              !text.isEmpty else {
            return "（读不到 boot.log）"
        }
        let limit = 2400
        if text.count <= limit { return text }
        return "…（前略）\n" + String(text.suffix(limit))
    }

    // MARK: 行构造

    private func addTitle(_ text: String) {
        let label = UILabel()
        label.text = text
        label.font = .systemFont(ofSize: 13, weight: .semibold)
        label.textColor = .secondaryLabel
        stack.addArrangedSubview(label)
        stack.setCustomSpacing(14, after: label)

        let line = UIView()
        line.backgroundColor = .separator
        line.translatesAutoresizingMaskIntoConstraints = false
        line.heightAnchor.constraint(equalToConstant: 0.5).isActive = true
        stack.insertArrangedSubview(line, at: stack.arrangedSubviews.count)
    }

    private func addRow(_ key: String, _ value: String, mono: Bool = false) {
        let row = UIStackView()
        row.axis = .horizontal
        row.spacing = 8
        row.alignment = .top

        if !key.isEmpty {
            let k = UILabel()
            k.text = key
            k.font = .systemFont(ofSize: 12)
            k.textColor = .secondaryLabel
            k.setContentHuggingPriority(.required, for: .horizontal)
            k.setContentCompressionResistancePriority(.required, for: .horizontal)
            row.addArrangedSubview(k)
        }

        let v = UILabel()
        v.text = value
        v.numberOfLines = 0
        v.font = mono ? .monospacedSystemFont(ofSize: 10.5, weight: .regular)
                      : .systemFont(ofSize: 12)
        v.textColor = .label
        row.addArrangedSubview(v)

        stack.addArrangedSubview(row)
    }

    private func addStatus(_ name: String, _ ok: Bool) {
        let row = UIStackView()
        row.axis = .horizontal
        row.spacing = 8
        row.alignment = .top

        let badge = UILabel()
        badge.text = ok ? "OK" : "NO"
        badge.font = .monospacedSystemFont(ofSize: 11, weight: .bold)
        badge.textColor = ok ? .systemGreen : .systemRed
        badge.setContentHuggingPriority(.required, for: .horizontal)
        row.addArrangedSubview(badge)

        let label = UILabel()
        label.text = name
        label.numberOfLines = 0
        label.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        label.textColor = .label
        row.addArrangedSubview(label)

        stack.addArrangedSubview(row)
    }

    private func addNote(_ text: String) {
        let box = UIView()
        box.backgroundColor = .secondarySystemBackground
        box.layer.cornerRadius = 8
        box.layer.masksToBounds = true

        let label = UILabel()
        label.text = text
        label.numberOfLines = 0
        label.font = .monospacedSystemFont(ofSize: 10.5, weight: .regular)
        label.textColor = .secondaryLabel
        label.translatesAutoresizingMaskIntoConstraints = false

        box.addSubview(label)
        NSLayoutConstraint.activate([
            label.topAnchor.constraint(equalTo: box.topAnchor, constant: 10),
            label.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: 10),
            label.trailingAnchor.constraint(equalTo: box.trailingAnchor, constant: -10),
            label.bottomAnchor.constraint(equalTo: box.bottomAnchor, constant: -10)
        ])
        stack.addArrangedSubview(box)
    }
}
