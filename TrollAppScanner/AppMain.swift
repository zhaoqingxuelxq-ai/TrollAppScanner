//
//  AppMain.swift
//  TrollAppScanner
//
//  程序入口 + 主列表界面
//

import SwiftUI
import UIKit

@main
struct TrollAppScannerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
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

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            let result = AppScannerEngine.scan(options: ScanOptions()) { value, text in
                DispatchQueue.main.async {
                    self.progress = value
                    self.status = text
                }
            }
            DispatchQueue.main.async {
                self.apps = result
                self.environment = EnvironmentProbe.probe()
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
                if !model.hasScanned && !model.isScanning {
                    model.start()
                }
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
            Text(model.isScanning ? "正在扫描…" : "暂无数据")
                .font(.system(size: 15, weight: .medium))
                .foregroundColor(.secondary)
            if !model.isScanning {
                Text("如果列表为空，多半是 entitlements 没生效：\n本 tipa 必须通过 TrollStore 安装。")
                    .font(.system(size: 12))
                    .foregroundColor(Color(UIColor.tertiaryLabel))
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
                Button {
                    model.start()
                } label: {
                    Text("重新扫描")
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
                    if app.encrypted {
                        TagView(text: "加密", color: .blue)
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
