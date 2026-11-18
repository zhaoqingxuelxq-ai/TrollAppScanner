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
    var injectedLibs: [String] = []
    var externalLibs: [String] = []
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
