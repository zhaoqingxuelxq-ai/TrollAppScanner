//
//  Export.swift
//  TrollAppScanner
//
//  导出 JSON / CSV / 文本报告
//

import Foundation

enum ExportFormat {
    case json
    case csv
    case report
}

enum Exporter {

    // MARK: 落盘

    static func write(apps: [AppRecord], format: ExportFormat) -> URL? {
        guard !apps.isEmpty else { return nil }

        let stamp = timestamp()
        let fileName: String
        var data = Data()

        switch format {
        case .json:
            fileName = "AppScanner-\(stamp).json"
            if let payload = jsonData(apps) { data = payload }
        case .csv:
            fileName = "AppScanner-\(stamp).csv"
            data = csvData(apps)
        case .report:
            fileName = "AppScanner-\(stamp).txt"
            data = reportData(apps)
        }

        guard !data.isEmpty else { return nil }

        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(fileName)
        do {
            try data.write(to: url, options: .atomic)
            return url
        } catch {
            return nil
        }
    }

    // MARK: JSON

    static func jsonData(_ apps: [AppRecord]) -> Data? {
        var array: [[String: Any]] = []

        for record in apps {
            var dict: [String: Any] = [
                "name": record.name,
                "bundleID": record.bundleID,
                "version": record.version,
                "build": record.build,
                "minimumOS": record.minimumOS,
                "kind": record.kind.rawValue,
                "origin": record.origin,
                "bundlePath": record.bundlePath,
                "executable": record.executable,
                "sizeBytes": record.sizeBytes,
                "sizeText": record.sizeText,
                "architectures": record.architectures,
                "encrypted": record.encrypted,
                "urlSchemes": record.urlSchemes,
                "appGroups": record.appGroups,
                "injectedLibs": record.injectedLibs,
                "externalLibs": record.externalLibs,
                "privacyKeys": record.privacyKeys,
                "isDuplicate": record.isDuplicate,
                "notes": record.notes
            ]

            if let container = record.containerPath {
                dict["containerPath"] = container
            }

            if let date = record.installDate {
                let formatter = DateFormatter()
                formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
                dict["installDate"] = formatter.string(from: date)
            }

            var signature: [String: Any] = [
                "identifier": record.sign.identifier,
                "teamID": record.sign.teamID,
                "adhoc": record.sign.isAdhoc,
                "platform": record.sign.isPlatform,
                "digest": record.sign.digest
            ]
            var entitlements: [String: String] = [:]
            for key in record.sign.entitlements.keys {
                entitlements[key] = printableValue(record.sign.entitlements[key])
            }
            signature["entitlements"] = entitlements
            dict["signature"] = signature

            var extensions: [[String: String]] = []
            for item in record.extensions {
                extensions.append(["bundleID": item.bundleID, "name": item.name])
            }
            dict["extensions"] = extensions

            array.append(dict)
        }

        return try? JSONSerialization.data(withJSONObject: array, options: [.prettyPrinted, .sortedKeys])
    }

    // MARK: CSV

    static func csvData(_ apps: [AppRecord]) -> Data {
        let header = [
            "名称", "BundleID", "版本", "Build", "类型", "来源",
            "体积(字节)", "体积", "架构", "加密", "签名类型", "TeamID",
            "安装路径", "数据容器", "注入库", "扩展数", "安装时间"
        ]

        var lines: [String] = []
        lines.append(header.map { escape($0) }.joined(separator: ","))

        for app in apps {
            var signatureType = "unsigned"
            if app.sign.hasSignature {
                signatureType = app.sign.isAdhoc ? "adhoc" : "certificate"
            }
            let row = [
                app.name,
                app.bundleID,
                app.version,
                app.build,
                app.kind.rawValue,
                app.origin,
                "\(app.sizeBytes)",
                app.sizeText,
                app.architectures.joined(separator: "|"),
                app.encrypted ? "是" : "否",
                signatureType,
                app.sign.teamID,
                app.bundlePath,
                app.containerPath ?? "",
                app.injectedLibs.joined(separator: "|"),
                "\(app.extensions.count)",
                humanDate(app.installDate)
            ]
            lines.append(row.map { escape($0) }.joined(separator: ","))
        }

        let text = lines.joined(separator: "\r\n")
        var data = Data([0xEF, 0xBB, 0xBF])   // UTF-8 BOM，Excel 友好
        data.append(Data(text.utf8))
        return data
    }

    static func escape(_ value: String) -> String {
        if value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r") {
            let escaped = value.replacingOccurrences(of: "\"", with: "\"\"")
            return "\"" + escaped + "\""
        }
        return value
    }

    // MARK: 文本报告

    static func reportData(_ apps: [AppRecord]) -> Data {
        var lines: [String] = []
        let totalSize = apps.reduce(Int64(0)) { $0 + $1.sizeBytes }
        let injected = apps.filter { !$0.injectedLibs.isEmpty }
        let duplicates = apps.filter { $0.isDuplicate }
        let encrypted = apps.filter { $0.encrypted }

        lines.append("==============================================")
        lines.append("        TrollAppScanner  安装包清单报告")
        lines.append("==============================================")
        lines.append("生成时间 : \(humanDate(Date()))")
        lines.append("安装包数 : \(apps.count)")
        lines.append("总体积   : \(humanSize(totalSize))")
        lines.append("含注入库 : \(injected.count)")
        lines.append("加密包体 : \(encrypted.count)")
        lines.append("重复副本 : \(duplicates.count)")
        lines.append("")

        let groups: [(name: String, list: [AppRecord])] = [
            ("用户 / 侧载应用", apps.filter { $0.kind == .user }),
            ("系统应用", apps.filter { $0.kind == .system })
        ]

        for group in groups {
            lines.append("----------------------------------------------")
            lines.append("\(group.name)（\(group.list.count) 个）")
            lines.append("----------------------------------------------")
            var index = 0
            for app in group.list {
                index += 1
                lines.append("")
                lines.append("[\(index)] \(app.name)")
                lines.append("    Bundle ID : \(app.bundleID)")
                lines.append("    版本      : \(app.version) (\(app.build))")
                lines.append("    来源      : \(app.origin)")
                lines.append("    体积      : \(app.sizeText)")
                lines.append("    架构      : \(app.architectures.isEmpty ? "-" : app.architectures.joined(separator: " / "))")
                lines.append("    加密      : \(app.encrypted ? "是" : "否")")
                if app.sign.hasSignature {
                    lines.append("    签名      : \(app.sign.isAdhoc ? "Ad-hoc" : "证书") / Team: \(app.sign.teamID.isEmpty ? "-" : app.sign.teamID)")
                } else {
                    lines.append("    签名      : 未读取到")
                }
                if !app.injectedLibs.isEmpty {
                    lines.append("    注入库    :")
                    for lib in app.injectedLibs {
                        lines.append("        - \(lib)")
                    }
                }
                lines.append("    安装路径  : \(app.bundlePath)")
                if let container = app.containerPath {
                    lines.append("    数据容器  : \(container)")
                }
                if !app.extensions.isEmpty {
                    lines.append("    扩展      : \(app.extensions.count) 个")
                }
                if let note = app.notes.first {
                    lines.append("    备注      : \(note)")
                }
            }
            lines.append("")
        }

        lines.append("==============================================")
        lines.append("报告结束 · TrollAppScanner")
        lines.append("==============================================")

        return Data(lines.joined(separator: "\n").utf8)
    }

    // MARK: 时间戳

    static func timestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }
}
