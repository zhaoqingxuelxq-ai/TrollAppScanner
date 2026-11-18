//
//  Models.swift
//  TrollAppScanner
//
//  数据模型 / 格式化工具
//

import Foundation
import UIKit

// MARK: - 安装包类型

enum AppKind: String {
    case system = "系统"
    case user   = "用户"
}

// MARK: - 应用扩展 (appex)

struct AppExtension: Identifiable {
    var id: String { bundleID }
    var bundleID: String = ""
    var name: String = ""
    var path: String = ""
}

// MARK: - 代码签名信息

struct CodeSignInfo {
    var hasSignature: Bool = false
    var identifier: String = ""
    var teamID: String = ""
    var isAdhoc: Bool = false
    var isPlatform: Bool = false
    var digest: String = ""
    var entitlements: [String: Any] = [:]

    /// 高亮提示用的危险 / 高权限 entitlement
    var sensitiveEntitlements: [String] {
        let keys = [
            "platform-application",
            "com.apple.private.security.no-sandbox",
            "com.apple.private.security.container-required",
            "get-task-allow",
            "dynamic-codesigning",
            "run-unsigned-code",
            "task_for_pid-allow",
            "com.apple.private.skip-library-validation",
            "com.apple.private.cs.debugger",
            "com.apple.private.mobileinstall.allowedSPI",
            "com.apple.private.amfi.can-load-cdhash"
        ]
        return entitlements.keys.filter { keys.contains($0) }.sorted()
    }
}

// MARK: - 描述文件（embedded.mobileprovision）信息

struct ProvisionInfo {
    var exists: Bool = false
    var name: String = ""
    var appIDName: String = ""
    var teamName: String = ""
    var teamID: String = ""
    var uuid: String = ""
    var applicationIdentifier: String = ""
    var creationDate: Date? = nil
    var expirationDate: Date? = nil
    var provisionedDeviceCount: Int = 0
    var provisionsAllDevices: Bool = false
    var platforms: [String] = []

    var isExpired: Bool {
        guard let expiration = expirationDate else { return false }
        return expiration < Date()
    }

    /// 剩余天数，已过期则为负数
    var daysRemaining: Int? {
        guard let expiration = expirationDate else { return nil }
        return Calendar.current.dateComponents([.day], from: Date(), to: expiration).day
    }

    var kindText: String {
        if provisionsAllDevices { return "企业签（In-House）" }
        if provisionedDeviceCount > 0 { return "描述文件（Ad Hoc / 开发）" }
        return "App Store（无设备限制）"
    }
}

// MARK: - 单个安装包记录

struct AppRecord: Identifiable {
    var id: String = ""
    var bundleID: String = ""
    var name: String = ""
    var displayName: String = ""
    var version: String = "-"
    var build: String = "-"
    var minimumOS: String = "-"
    var executable: String = ""
    var bundlePath: String = ""
    var containerPath: String? = nil
    var kind: AppKind = .user
    var origin: String = "未知"
    var installDate: Date? = nil
    var sizeBytes: Int64 = 0
    var architectures: [String] = []
    var encrypted: Bool = false
    var sign: CodeSignInfo = CodeSignInfo()
    var provision: ProvisionInfo = ProvisionInfo()

    // 直接读 Mach-O 得到的信息，比 Info.plist 里的字段可靠（后者可以被改）
    var binaryUUID: String = ""
    var buildSDK: String = ""
    var binaryMinOS: String = ""

    var injectedLibs: [String] = []
    var externalLibs: [String] = []
    /// 链接了但实际找不到文件的库（@rpath 解析失败）——这类 App 启动会直接闪退
    var missingLibs: [String] = []

    var urlSchemes: [String] = []
    var appGroups: [String] = []
    var extensions: [AppExtension] = []
    var privacyKeys: [String] = []
    var iconPath: String? = nil
    var infoPlistXML: String = ""
    var isDuplicate: Bool = false
    var notes: [String] = []

    var sizeText: String { humanSize(sizeBytes) }

    var typeText: String {
        if !extensions.isEmpty { return "\(kind.rawValue) · \(extensions.count) 个扩展" }
        return kind.rawValue
    }

    /// 列表里显示的一行摘要
    var summaryLine: String {
        var parts: [String] = []
        parts.append("v" + version)
        if sizeBytes > 0 { parts.append(sizeText) }
        parts.append(origin)
        if encrypted { parts.append("加密") }
        return parts.joined(separator: "  ·  ")
    }
}

// MARK: - 扫描选项

struct ScanOptions {
    var includeSystemApps: Bool = true
    var computeSize: Bool = true
    var readEntitlements: Bool = true
    var readMachO: Bool = true
    var includeExtensions: Bool = true
}

// MARK: - 格式化工具

func humanSize(_ bytes: Int64) -> String {
    if bytes <= 0 { return "-" }
    let units = ["B", "KB", "MB", "GB", "TB"]
    var value = Double(bytes)
    var index = 0
    while value >= 1024.0 && index < units.count - 1 {
        value /= 1024.0
        index += 1
    }
    if index == 0 {
        return String(format: "%.0f %@", value, units[index])
    }
    return String(format: "%.1f %@", value, units[index])
}

func humanDate(_ date: Date?) -> String {
    guard let date = date else { return "-" }
    let f = DateFormatter()
    f.dateFormat = "yyyy-MM-dd HH:mm"
    return f.string(from: date)
}

/// 把 entitlement 的任意值转成可读字符串
func printableValue(_ value: Any?) -> String {
    guard let value = value else { return "null" }
    if let boolValue = value as? Bool { return boolValue ? "true" : "false" }
    if let stringValue = value as? String { return stringValue }
    if let numberValue = value as? NSNumber { return numberValue.stringValue }
    if let arrayValue = value as? [Any] {
        let inner = arrayValue.map { printableValue($0) }.joined(separator: ", ")
        return "[" + inner + "]"
    }
    if let dictValue = value as? [String: Any] {
        let inner = dictValue.keys.sorted().map { "\($0): \(printableValue(dictValue[$0]))" }.joined(separator: ", ")
        return "{" + inner + "}"
    }
    if let dataValue = value as? Data {
        return "Data(\(dataValue.count) bytes)"
    }
    return String(describing: value)
}

// MARK: - 启动日志
//
// App 在设备上一启动就闪退时，界面上什么都看不到。
// 这里把关键节点落到文件，能反推是「没进 Swift 代码」还是「死在扫描里」：
//   Documents/boot.log —— 用「文件」App 就能取（Info.plist 已开 UIFileSharingEnabled）
//   /tmp/boot.log      —— no-sandbox 生效时可直接读
enum Boot {
    static let docPath: String = {
        let home = NSHomeDirectory()
        return home + "/Documents/boot.log"
    }()

    static func log(_ message: String) {
        let stamp = String(format: "%.3f", Date().timeIntervalSince1970)
        let line = stamp + " " + message + "\n"
        guard let data = line.data(using: .utf8) else { return }

        append(data, to: docPath)
        append(data, to: "/tmp/boot.log")
    }

    private static func append(_ data: Data, to path: String) {
        let fm = FileManager.default
        let dir = (path as NSString).deletingLastPathComponent
        if !fm.fileExists(atPath: dir) {
            try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        }
        if let handle = FileHandle(forWritingAtPath: path) {
            handle.seekToEndOfFile()
            handle.write(data)
            handle.closeFile()
        } else {
            try? data.write(to: URL(fileURLWithPath: path))
        }
    }

    /// 覆盖写「当前正在处理的对象」。
    /// 扫描中途崩掉时，这个文件里的内容就是最后一个经手的安装包，
    /// 能直接定位到是哪个 App 触发的崩溃。
    static func mark(_ text: String) {
        guard let data = text.data(using: .utf8) else { return }
        let doc = NSHomeDirectory() + "/Documents/current.txt"
        let dir = (doc as NSString).deletingLastPathComponent
        if !FileManager.default.fileExists(atPath: dir) {
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        }
        try? data.write(to: URL(fileURLWithPath: doc))
        try? data.write(to: URL(fileURLWithPath: "/tmp/current.txt"))
    }
}

// MARK: - 图标缓存（带降采样）

final class IconCache {
    static let shared = IconCache()
    private let cache = NSCache<NSString, UIImage>()

    private init() {
        cache.countLimit = 400
    }

    func image(at path: String?) -> UIImage? {
        guard let path = path, !path.isEmpty else { return nil }
        let key = path as NSString
        if let cached = cache.object(forKey: key) { return cached }
        guard let source = UIImage(contentsOfFile: path) else { return nil }
        let target = CGSize(width: 120, height: 120)
        let renderer = UIGraphicsImageRenderer(size: target)
        let small = renderer.image { _ in
            source.draw(in: CGRect(origin: .zero, size: target))
        }
        cache.setObject(small, forKey: key)
        return small
    }
}
