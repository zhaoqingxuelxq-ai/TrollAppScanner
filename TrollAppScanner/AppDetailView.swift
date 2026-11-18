//
//  AppDetailView.swift
//  TrollAppScanner
//
//  单个安装包详情 / 环境诊断
//
//  注意：SwiftUI 的 ViewBuilder 只提供到 10 个参数的 buildBlock 重载，
//  List 里直接堆十几个 Section 会报 "Extra argument in call"。
//  所以这里按模块拆成若干个 @ViewBuilder 计算属性，每个内部控制在 10 个以内。
//

import SwiftUI
import UIKit

struct AppDetailView: View {

    let app: AppRecord
    @State private var showRawPlist: Bool = false

    var body: some View {
        List {
            headerSection
            basicSection
            pathSection
            binarySection

            entitlementsSection
            injectionSection
            miscSection
            rawPlistSection
        }
        .listStyle(InsetGroupedListStyle())
        .navigationTitle(app.name)
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $showRawPlist) {
            RawPlistView(text: app.infoPlistXML)
        }
    }

    // MARK: - 头部

    @ViewBuilder
    private var headerSection: some View {
        Section {
            HStack(spacing: 14) {
                if let image = IconCache.shared.image(at: app.iconPath) {
                    Image(uiImage: image)
                        .resizable()
                        .frame(width: 58, height: 58)
                        .clipShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
                } else {
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .fill(Color(UIColor.secondarySystemBackground))
                        .frame(width: 58, height: 58)
                        .overlay(
                            Image(systemName: "shippingbox")
                                .font(.system(size: 24))
                                .foregroundColor(.secondary)
                        )
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text(app.name)
                        .font(.system(size: 17, weight: .semibold))
                        .lineLimit(2)
                    Text(app.bundleID)
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                        .lineLimit(2)
                    HStack(spacing: 5) {
                        TagView(text: app.kind.rawValue, color: .accentColor)
                        TagView(text: app.origin, color: .secondary)
                        if app.encrypted { TagView(text: "加密", color: .blue) }
                        if app.isDuplicate { TagView(text: "重复", color: .orange) }
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.vertical, 4)
        }
    }

    // MARK: - 基本信息

    @ViewBuilder
    private var basicSection: some View {
        Section(header: Text("基本信息")) {
            KeyValueRow(key: "显示名称", value: app.name)
            KeyValueRow(key: "Bundle ID", value: app.bundleID, mono: true)
            KeyValueRow(key: "版本", value: "\(app.version) (\(app.build))")
            KeyValueRow(key: "最低系统", value: "iOS \(app.minimumOS)")
            KeyValueRow(key: "类型", value: app.typeText)
            KeyValueRow(key: "来源", value: app.origin)
            KeyValueRow(key: "体积", value: app.sizeText)
            KeyValueRow(key: "安装时间", value: humanDate(app.installDate))
        }
    }

    // MARK: - 路径

    @ViewBuilder
    private var pathSection: some View {
        Section(header: Text("路径")) {
            CopyRow(title: "安装包路径", value: app.bundlePath)
            if let container = app.containerPath {
                CopyRow(title: "数据容器", value: container)
            }
            if !app.executable.isEmpty {
                CopyRow(title: "可执行文件", value: app.bundlePath + "/" + app.executable)
            }
        }
    }

    // MARK: - 二进制与签名

    @ViewBuilder
    private var binarySection: some View {
        Section(header: Text("二进制与签名")) {
            if !app.architectures.isEmpty {
                KeyValueRow(key: "架构", value: app.architectures.joined(separator: " / "))
            }
            KeyValueRow(key: "加密 (cryptid)", value: app.encrypted ? "是" : "否")
            if app.sign.hasSignature {
                KeyValueRow(key: "签名标识", value: app.sign.identifier.isEmpty ? "-" : app.sign.identifier, mono: true)
                KeyValueRow(key: "Team ID", value: app.sign.teamID.isEmpty ? "无（无团队标识）" : app.sign.teamID, mono: true)
                KeyValueRow(key: "签名类型", value: app.sign.isAdhoc ? "Ad-hoc（ldid / TrollStore）" : "证书签名")
                KeyValueRow(key: "Platform 标记", value: app.sign.isPlatform ? "是" : "否")
                if !app.sign.digest.isEmpty {
                    KeyValueRow(key: "签名摘要", value: app.sign.digest, mono: true)
                }
            } else {
                KeyValueRow(key: "签名", value: "未读取到有效签名")
            }
        }
    }

    // MARK: - Entitlements

    @ViewBuilder
    private var entitlementsSection: some View {
        if !app.sign.sensitiveEntitlements.isEmpty {
            Section(header: Text("高权限 Entitlements")) {
                ForEach(app.sign.sensitiveEntitlements, id: \.self) { key in
                    KeyValueRow(key: key,
                                value: printableValue(app.sign.entitlements[key]),
                                highlight: true,
                                mono: true)
                }
            }
        }

        if !app.sign.entitlements.isEmpty {
            Section(header: Text("全部 Entitlements（\(app.sign.entitlements.count) 项）")) {
                ForEach(app.sign.entitlements.keys.sorted(), id: \.self) { key in
                    KeyValueRow(key: key,
                                value: printableValue(app.sign.entitlements[key]),
                                mono: true)
                }
            }
        }
    }

    // MARK: - 注入库

    @ViewBuilder
    private var injectionSection: some View {
        if !app.injectedLibs.isEmpty {
            Section(header: Text("检测到注入 / Hook 库（\(app.injectedLibs.count)）")) {
                ForEach(app.injectedLibs, id: \.self) { lib in
                    Text(lib)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }

        if !app.externalLibs.isEmpty {
            Section(header: Text("外部绝对路径依赖（\(app.externalLibs.count)）")) {
                ForEach(app.externalLibs, id: \.self) { lib in
                    Text(lib)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    // MARK: - 杂项（URL Schemes / App Groups / 扩展 / 隐私 / 备注）

    @ViewBuilder
    private var miscSection: some View {
        if !app.urlSchemes.isEmpty {
            Section(header: Text("URL Schemes（\(app.urlSchemes.count)）")) {
                ForEach(app.urlSchemes, id: \.self) { scheme in
                    CopyRow(title: scheme, value: scheme + "://")
                }
            }
        }

        if !app.appGroups.isEmpty {
            Section(header: Text("App Groups（\(app.appGroups.count)）")) {
                ForEach(app.appGroups, id: \.self) { group in
                    Text(group)
                        .font(.system(size: 11.5, design: .monospaced))
                }
            }
        }

        if !app.extensions.isEmpty {
            Section(header: Text("App 扩展（\(app.extensions.count)）")) {
                ForEach(app.extensions) { item in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(item.name)
                            .font(.system(size: 13, weight: .medium))
                        Text(item.bundleID)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    .padding(.vertical, 2)
                }
            }
        }

        if !app.privacyKeys.isEmpty {
            Section(header: Text("隐私权限声明（\(app.privacyKeys.count)）")) {
                ForEach(app.privacyKeys, id: \.self) { key in
                    Text(key.replacingOccurrences(of: "UsageDescription", with: ""))
                        .font(.system(size: 12, design: .monospaced))
                }
            }
        }

        if !app.notes.isEmpty {
            Section(header: Text("备注")) {
                ForEach(app.notes, id: \.self) { note in
                    Text(note)
                        .font(.system(size: 12))
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    // MARK: - 原始 plist

    @ViewBuilder
    private var rawPlistSection: some View {
        Section {
            Button {
                showRawPlist = true
            } label: {
                HStack {
                    Image(systemName: "doc.text.magnifyingglass")
                    Text("查看完整 Info.plist")
                    Spacer()
                    Text("\(app.infoPlistXML.count / 1024) KB")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
            }
        }
    }
}

// MARK: - 通用行

struct KeyValueRow: View {
    let key: String
    let value: String
    var highlight: Bool = false
    var mono: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(key)
                .font(.system(size: 11.5, design: .monospaced))
                .foregroundColor(highlight ? Color.orange : Color.secondary)
            Text(value)
                .font(mono ? .system(size: 11.5, design: .monospaced) : .system(size: 12.5))
                .foregroundColor(highlight ? Color.orange : Color.primary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 2)
    }
}

struct CopyRow: View {
    let title: String
    let value: String
    @State private var copied: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.system(size: 11))
                .foregroundColor(.secondary)
            HStack(alignment: .top, spacing: 8) {
                Text(value)
                    .font(.system(size: 11.5, design: .monospaced))
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button {
                    UIPasteboard.general.string = value
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
                        copied = false
                    }
                } label: {
                    Image(systemName: copied ? "checkmark.circle.fill" : "doc.on.doc")
                        .font(.system(size: 13))
                        .foregroundColor(copied ? Color.green : Color.accentColor)
                }
                .buttonStyle(PlainButtonStyle())
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - 原始 Info.plist

struct RawPlistView: View {
    let text: String
    @Environment(\.presentationMode) private var presentationMode

    var body: some View {
        NavigationView {
            ScrollView {
                Text(text.isEmpty ? "（空）" : text)
                    .font(.system(size: 10, design: .monospaced))
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .navigationTitle("Info.plist")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button {
                        UIPasteboard.general.string = text
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("关闭") {
                        presentationMode.wrappedValue.dismiss()
                    }
                }
            }
        }
        .navigationViewStyle(StackNavigationViewStyle())
    }
}

// MARK: - 环境诊断

struct DiagnosticsView: View {

    @Environment(\.presentationMode) private var presentationMode
    @State private var info = EnvironmentInfo()

    var body: some View {
        NavigationView {
            List {
                deviceSection
                readAbilitySection
                entitlementsSection
                environmentSection
                noteSection
            }
            .listStyle(InsetGroupedListStyle())
            .navigationTitle("环境诊断")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("关闭") {
                        presentationMode.wrappedValue.dismiss()
                    }
                }
            }
            .onAppear {
                info = EnvironmentProbe.probe()
            }
        }
        .navigationViewStyle(StackNavigationViewStyle())
    }

    @ViewBuilder
    private var deviceSection: some View {
        Section(header: Text("设备")) {
            KeyValueRow(key: "设备型号", value: info.deviceModel)
            KeyValueRow(key: "系统版本", value: "iOS " + info.systemVersion)
            KeyValueRow(key: "运行用户 uid", value: "\(info.uid)" + (info.uid == 501 ? "（mobile）" : ""))
            KeyValueRow(key: "App 路径", value: info.appPath, mono: true)
        }
    }

    @ViewBuilder
    private var readAbilitySection: some View {
        Section(header: Text("越界读取能力")) {
            statusRow("/var/containers/Bundle/Application", info.canReadBundleRoot)
            statusRow("/Applications", info.canReadApplications)
            statusRow("/var/mobile/Containers/Data/Application", info.canReadContainers)
        }
    }

    @ViewBuilder
    private var entitlementsSection: some View {
        Section(header: Text("自身 Entitlements")) {
            statusRow("com.apple.private.security.no-sandbox", info.hasNoSandbox)
            statusRow("platform-application", info.hasPlatformApp)
            if !info.entitlementKeys.isEmpty {
                ForEach(info.entitlementKeys, id: \.self) { key in
                    Text(key)
                        .font(.system(size: 11, design: .monospaced))
                }
            } else {
                KeyValueRow(key: "读取结果", value: "未解析到签名信息")
            }
        }
    }

    @ViewBuilder
    private var environmentSection: some View {
        Section(header: Text("环境特征")) {
            statusRow("TrollStore 运行痕迹", info.trollStoreDetected)
            if info.jailbreakPaths.isEmpty {
                KeyValueRow(key: "越狱路径", value: "未发现")
            } else {
                ForEach(info.jailbreakPaths, id: \.self) { path in
                    Text(path)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.orange)
                }
            }
        }
    }

    @ViewBuilder
    private var noteSection: some View {
        Section(header: Text("说明")) {
            Text("本工具依赖 no-sandbox / platform-application 两个 entitlement 才能越出沙盒读取全系统安装包。如果上面的读取能力全部为 NO，说明签名未生效，请重新用 TrollStore 安装本 tipa。")
                .font(.system(size: 12))
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func statusRow(_ title: String, _ ok: Bool) -> some View {
        HStack(spacing: 8) {
            Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.system(size: 14))
                .foregroundColor(ok ? Color.green : Color.red)
            Text(title)
                .font(.system(size: 12, design: .monospaced))
                .lineLimit(2)
            Spacer(minLength: 4)
            Text(ok ? "OK" : "NO")
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(ok ? Color.green : Color.red)
        }
        .padding(.vertical, 2)
    }
}
