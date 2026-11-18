//
//  Scanner.swift
//  TrollAppScanner
//
//  核心：目录枚举 / Info.plist / Mach-O / CodeSignature(entitlements) / 容器映射
//

import Foundation
import UIKit
import CryptoKit
import Darwin

// MARK: - 二进制读取工具

private func readBytes(_ handle: FileHandle, offset: Int, length: Int) -> Data? {
    guard offset >= 0, length > 0 else { return nil }
    do {
        try handle.seek(toOffset: UInt64(offset))
    } catch {
        return nil
    }
    let data = handle.readData(ofLength: length)
    if data.isEmpty { return nil }
    return data
}

private func be32(_ data: Data, _ offset: Int) -> UInt32 {
    let start = data.startIndex
    guard offset >= 0, start + offset + 4 <= data.endIndex else { return 0 }
    let b0 = UInt32(data[start + offset])
    let b1 = UInt32(data[start + offset + 1])
    let b2 = UInt32(data[start + offset + 2])
    let b3 = UInt32(data[start + offset + 3])
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

private func be64(_ data: Data, _ offset: Int) -> UInt64 {
    let start = data.startIndex
    guard offset >= 0, start + offset + 8 <= data.endIndex else { return 0 }
    var value: UInt64 = 0
    for i in 0..<8 {
        value = (value << 8) | UInt64(data[start + offset + i])
    }
    return value
}

private func cString(_ data: Data, _ offset: Int) -> String {
    let start = data.startIndex
    guard offset >= 0, start + offset < data.endIndex else { return "" }
    var end = start + offset
    while end < data.endIndex && data[end] != 0 {
        end += 1
    }
    guard end > start + offset else { return "" }
    let slice = data.subdata(in: (start + offset)..<end)
    return String(data: slice, encoding: .utf8) ?? ""
}

// MARK: - Mach-O 解析

struct MachOResult {
    var architectures: [String] = []
    var encrypted: Bool = false
    var dylibs: [String] = []
    var codeSigOffset: Int = 0
    var codeSigSize: Int = 0

    var uuid: String = ""
    var platformLabel: String = ""
    var minOSVersion: String = ""
    var sdkVersion: String = ""
    var rpaths: [String] = []
}

enum MachO {

    static let MH_MAGIC: UInt32     = 0xfeedface
    static let MH_MAGIC_64: UInt32  = 0xfeedfacf
    static let MH_CIGAM: UInt32     = 0xcefaedfe
    static let MH_CIGAM_64: UInt32  = 0xcffaedfe
    static let FAT_MAGIC: UInt32    = 0xcafebabe
    static let FAT_MAGIC_64: UInt32 = 0xcafebabf

    static func parse(path: String) -> MachOResult? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { handle.closeFile() }

        guard let head = readBytes(handle, offset: 0, length: 4096), head.count >= 8 else { return nil }
        let magic = be32(head, 0)
        var result = MachOResult()

        if magic == FAT_MAGIC || magic == FAT_MAGIC_64 {
            let isFat64 = (magic == FAT_MAGIC_64)
            let count = Int(be32(head, 4))
            let archSize = isFat64 ? 32 : 20
            var cursor = 8
            var slices: [(cpu: UInt32, sub: UInt32, off: Int)] = []
            for _ in 0..<min(max(count, 0), 32) {
                guard cursor + archSize <= head.count else { break }
                let cpu = be32(head, cursor)
                let sub = be32(head, cursor + 4)
                let fileOffset: Int
                if isFat64 {
                    fileOffset = Int(be64(head, cursor + 8))
                } else {
                    fileOffset = Int(be32(head, cursor + 8))
                }
                slices.append((cpu, sub, fileOffset))
                cursor += archSize
            }
            guard !slices.isEmpty else { return nil }

            // 架构列表去重（同一个 cpu 可能被重复登记）
            var archList: [String] = []
            for slice in slices {
                let name = cpuName(slice.cpu, slice.sub)
                if !archList.contains(name) { archList.append(name) }
            }
            result.architectures = archList

            // 设备上真正执行的是 arm64 / arm64e 切片，加密状态与签名都以它为准，
            // 不能像原来那样「谁先解析成功就用谁」——fat 表顺序不保证 arm64 在前
            let preferred = slices.filter { $0.cpu == 0x0100000C }
                + slices.filter { $0.cpu != 0x0100000C }
            for slice in preferred {
                if let single = parseSlice(handle: handle, base: slice.off) {
                    result.encrypted = single.encrypted
                    result.dylibs = single.dylibs
                    result.codeSigOffset = single.codeSigOffset
                    result.codeSigSize = single.codeSigSize
                    result.uuid = single.uuid
                    result.platformLabel = single.platformLabel
                    result.minOSVersion = single.minOSVersion
                    result.sdkVersion = single.sdkVersion
                    result.rpaths = single.rpaths
                    break
                }
            }
        } else if magic == MH_MAGIC_64 || magic == MH_CIGAM_64 || magic == MH_MAGIC || magic == MH_CIGAM {
            guard let header = readBytes(handle, offset: 0, length: 32), header.count >= 28 else { return nil }
            guard let single = parseSlice(handle: handle, base: 0) else { return nil }
            result.encrypted = single.encrypted
            result.dylibs = single.dylibs
            result.codeSigOffset = single.codeSigOffset
            result.codeSigSize = single.codeSigSize
            result.uuid = single.uuid
            result.platformLabel = single.platformLabel
            result.minOSVersion = single.minOSVersion
            result.sdkVersion = single.sdkVersion
            result.rpaths = single.rpaths
            result.architectures = [cpuName(be32(header, 4), be32(header, 8))]
        } else {
            return nil
        }
        return result
    }

    private static func parseSlice(handle: FileHandle, base: Int) -> MachOResult? {
        guard let header = readBytes(handle, offset: base, length: 32), header.count >= 28 else { return nil }
        let magic = be32(header, 0)
        var is64 = false
        if magic == MH_MAGIC_64 || magic == MH_CIGAM_64 {
            is64 = true
        } else if magic == MH_MAGIC || magic == MH_CIGAM {
            is64 = false
        } else {
            return nil
        }

        let ncmds = Int(be32(header, 16))
        let sizeofcmds = Int(be32(header, 20))
        guard ncmds > 0, ncmds < 100000, sizeofcmds > 0, sizeofcmds < 8 * 1024 * 1024 else { return nil }
        let headerSize = is64 ? 32 : 28
        guard let body = readBytes(handle, offset: base + headerSize, length: sizeofcmds) else { return nil }

        var result = MachOResult()
        var cursor = 0
        for _ in 0..<ncmds {
            guard cursor + 8 <= body.count else { break }
            let cmd = be32(body, cursor)
            let cmdsize = Int(be32(body, cursor + 4))
            guard cmdsize >= 8, cursor + cmdsize <= body.count else { break }

            switch cmd {
            case 0x0C, 0x80000018, 0x8000001F, 0x80000023:
                let nameOffset = Int(be32(body, cursor + 8))
                if nameOffset > 0, cursor + nameOffset < body.count {
                    let name = cString(body, cursor + nameOffset)
                    if !name.isEmpty { result.dylibs.append(name) }
                }
            case 0x2C:
                if cursor + 20 <= body.count, be32(body, cursor + 16) != 0 { result.encrypted = true }
            case 0x21:
                if cursor + 20 <= body.count, be32(body, cursor + 16) != 0 { result.encrypted = true }
            case 0x1D:
                if cursor + 16 <= body.count {
                    result.codeSigOffset = base + Int(be32(body, cursor + 8))
                    result.codeSigSize = Int(be32(body, cursor + 12))
                }
            case 0x1B:   // LC_UUID
                if cursor + 24 <= body.count {
                    result.uuid = uuidText(body, cursor + 8)
                }
            case 0x32:   // LC_BUILD_VERSION（Xcode 10+ 产出）
                if cursor + 24 <= body.count {
                    result.platformLabel = platformName(be32(body, cursor + 8))
                    result.minOSVersion = versionText(be32(body, cursor + 12))
                    result.sdkVersion = versionText(be32(body, cursor + 16))
                }
            case 0x25:   // LC_VERSION_MIN_IPHONEOS（老工具链）
                if cursor + 16 <= body.count {
                    result.platformLabel = "iOS"
                    result.minOSVersion = versionText(be32(body, cursor + 8))
                    result.sdkVersion = versionText(be32(body, cursor + 12))
                }
            case 0x8000001C:   // LC_RPATH
                if cursor + 12 <= body.count {
                    let pathOffset = Int(be32(body, cursor + 8))
                    if pathOffset > 0, cursor + pathOffset < body.count {
                        let path = cString(body, cursor + pathOffset)
                        if !path.isEmpty { result.rpaths.append(path) }
                    }
                }
            default:
                break
            }
            cursor += cmdsize
        }
        return result
    }

    /// LC_UUID 的 16 字节转标准 8-4-4-4-12 形式
    static func uuidText(_ data: Data, _ offset: Int) -> String {
        let start = data.startIndex
        guard offset + 16 <= data.count else { return "" }
        var bytes: [UInt8] = []
        for i in 0..<16 { bytes.append(data[start + offset + i]) }
        let groups: [ArraySlice<UInt8>] = [
            bytes[0..<4], bytes[4..<6], bytes[6..<8], bytes[8..<10], bytes[10..<16]
        ]
        return groups.map { group in
            group.map { String(format: "%02X", $0) }.joined()
        }.joined(separator: "-")
    }

    /// Mach-O 里的版本号是 nibble 编码：0x000D0200 → 13.2
    static func versionText(_ raw: UInt32) -> String {
        let major = raw >> 16
        let minor = (raw >> 8) & 0xFF
        let patch = raw & 0xFF
        if patch != 0 { return "\(major).\(minor).\(patch)" }
        return "\(major).\(minor)"
    }

    static func platformName(_ raw: UInt32) -> String {
        switch raw {
        case 1: return "macOS"
        case 2: return "iOS"
        case 3: return "tvOS"
        case 4: return "watchOS"
        case 5: return "bridgeOS"
        case 6: return "Mac Catalyst"
        case 7: return "iOS 模拟器"
        case 8: return "tvOS 模拟器"
        case 9: return "watchOS 模拟器"
        default: return "platform_\(raw)"
        }
    }

    static func cpuName(_ cpu: UInt32, _ sub: UInt32) -> String {
        switch cpu {
        case 0x0100000C:
            return ((sub & 0x00FFFFFF) == 2) ? "arm64e" : "arm64"
        case 0x0000000C:
            return "armv7"
        case 0x01000007:
            return "x86_64"
        case 0x00000007:
            return "i386"
        default:
            return String(format: "cpu_%x", cpu)
        }
    }
}

// MARK: - 代码签名 / Entitlements 解析

enum CodeSign {

    static func parse(path: String, offset: Int, size: Int) -> CodeSignInfo? {
        guard offset > 0, size >= 12 else { return nil }
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { handle.closeFile() }

        let limit = min(size, 4 * 1024 * 1024)
        guard let blob = readBytes(handle, offset: offset, length: limit), blob.count >= 12 else { return nil }
        guard be32(blob, 0) == 0xFADE0CC0 else { return nil }

        var info = CodeSignInfo()
        info.hasSignature = true

        let count = Int(be32(blob, 8))
        var entitlementsOffset: Int? = nil
        var codeDirectoryOffset: Int? = nil

        for i in 0..<min(max(count, 0), 64) {
            let base = 12 + i * 8
            guard base + 8 <= blob.count else { break }
            let type = be32(blob, base)
            let offsetValue = Int(be32(blob, base + 4))
            if type == 5 { entitlementsOffset = offsetValue }
            if type == 0 { codeDirectoryOffset = offsetValue }
        }

        if let eo = entitlementsOffset, eo + 8 <= blob.count {
            let magic = be32(blob, eo)
            let length = Int(be32(blob, eo + 4))
            if magic == 0xFADE7171, length >= 8, eo + length <= blob.count {
                let plistData = blob.subdata(in: (eo + 8)..<(eo + length))
                if let object = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil),
                   let dictionary = object as? [String: Any] {
                    info.entitlements = dictionary
                }
            }
        }

        if let co = codeDirectoryOffset, co + 44 <= blob.count {
            if be32(blob, co) == 0xFADE0C02 {
                let version = be32(blob, co + 8)
                let flags = be32(blob, co + 12)
                let identOffset = Int(be32(blob, co + 20))
                info.isAdhoc = (flags & 0x00000002) != 0
                if co + 39 <= blob.count {
                    info.isPlatform = blob[co + 38] != 0
                }
                if identOffset > 0, co + identOffset < blob.count {
                    info.identifier = cString(blob, co + identOffset)
                }
                if version >= 0x20200, co + 52 <= blob.count {
                    let teamOffset = Int(be32(blob, co + 48))
                    if teamOffset > 0, co + teamOffset < blob.count {
                        info.teamID = cString(blob, co + teamOffset)
                    }
                }
                let cdLength = Int(be32(blob, co + 4))
                if cdLength > 0, cdLength < 1024 * 1024, co + cdLength <= blob.count {
                    let cdData = blob.subdata(in: co..<(co + cdLength))
                    let digest = SHA256.hash(data: cdData)
                    let hex = digest.map { String(format: "%02x", Int($0)) }.joined()
                    info.digest = String(hex.prefix(24))
                }
            }
        }

        return info
    }
}

// MARK: - 描述文件（embedded.mobileprovision）解析

enum Provision {

    /// mobileprovision 是 CMS 签名包裹，正文里嵌了一段 XML plist，直接截出来解析。
    /// 不去验签（也没必要），只取「谁签的、给了什么权限、什么时候过期」。
    static func parse(bundlePath: String) -> ProvisionInfo? {
        let path = bundlePath + "/embedded.mobileprovision"
        let fm = FileManager.default
        guard fm.fileExists(atPath: path), let raw = fm.contents(atPath: path) else { return nil }

        guard let startRange = raw.range(of: Data("<?xml".utf8)),
              let endRange = raw.range(of: Data("</plist>".utf8)),
              startRange.lowerBound < endRange.upperBound else { return nil }

        let plistData = raw.subdata(in: startRange.lowerBound..<endRange.upperBound)
        guard let object = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil),
              let dict = object as? [String: Any] else { return nil }

        var info = ProvisionInfo()
        info.exists = true
        info.name = dict["Name"] as? String ?? ""
        info.appIDName = dict["AppIDName"] as? String ?? ""
        info.teamName = dict["TeamName"] as? String ?? ""
        if let teams = dict["TeamIdentifier"] as? [String], let first = teams.first {
            info.teamID = first
        }
        info.uuid = dict["UUID"] as? String ?? ""
        info.creationDate = dict["CreationDate"] as? Date
        info.expirationDate = dict["ExpirationDate"] as? Date
        info.provisionsAllDevices = (dict["ProvisionsAllDevices"] as? Bool) ?? false
        info.provisionedDeviceCount = (dict["ProvisionedDevices"] as? [Any])?.count ?? 0
        info.platforms = (dict["Platform"] as? [String]) ?? []

        if let entitlements = dict["Entitlements"] as? [String: Any] {
            info.applicationIdentifier = entitlements["application-identifier"] as? String ?? ""
        }
        return info
    }
}

// MARK: - 扫描引擎

enum AppScannerEngine {

    static let fm = FileManager.default

    static let bundleRoots: [String] = [
        "/Applications",
        "/System/Library/CoreServices/SystemApps",
        "/System/Library/CoreServices",
        "/var/containers/Bundle/Application"
    ]

    // MARK: 入口

    static func scan(options: ScanOptions,
                     update: @escaping (Double, String) -> Void) -> [AppRecord] {

        let post: (Double, String) -> Void = { progress, text in
            DispatchQueue.main.async { update(progress, text) }
        }

        post(0.02, "正在定位安装包目录…")
        let candidates = bundleCandidates(options: options)
        post(0.05, "发现 \(candidates.count) 个候选包，正在读取容器映射…")
        let containerMap = buildContainerMap()

        var records: [AppRecord] = []
        let total = max(candidates.count, 1)

        for (index, item) in candidates.enumerated() {
            let percentage = 0.08 + 0.88 * (Double(index) / Double(total))
            let shortName = (item.path as NSString).lastPathComponent
            post(percentage, "扫描 \(shortName)  [\(index + 1)/\(total)]")
            if let record = parseApp(bundlePath: item.path,
                                     kind: item.kind,
                                     containerMap: containerMap,
                                     options: options) {
                records.append(record)
            }
        }

        post(0.97, "整理与去重…")
        var counts: [String: Int] = [:]
        for record in records {
            counts[record.bundleID, default: 0] += 1
        }
        for index in 0..<records.count {
            let bundleID = records[index].bundleID
            let sameCount = counts[bundleID] ?? 0
            if sameCount > 1 {
                records[index].isDuplicate = true
                records[index].notes.append("存在 \(sameCount) 个相同 bundle id 的副本")
            }
        }

        records.sort { left, right in
            if left.kind != right.kind { return left.kind == .user }
            return left.name.localizedStandardCompare(right.name) == .orderedAscending
        }

        post(1.0, "扫描完成，共 \(records.count) 个安装包")
        return records
    }

    // MARK: 目录枚举

    static func bundleCandidates(options: ScanOptions) -> [(path: String, kind: AppKind)] {
        var output: [(path: String, kind: AppKind)] = []
        var seen = Set<String>()

        func add(_ path: String, _ kind: AppKind) {
            guard !seen.contains(path) else { return }
            seen.insert(path)
            output.append((path, kind))
        }

        if options.includeSystemApps {
            for path in subBundles(in: "/Applications", suffix: ".app") {
                add(path, .system)
            }
            for path in subBundles(in: "/System/Library/CoreServices/SystemApps", suffix: ".app") {
                add(path, .system)
            }
            for path in subBundles(in: "/System/Library/CoreServices", suffix: ".app") {
                add(path, .system)
            }
        }

        let userRoot = "/var/containers/Bundle/Application"
        if let containers = try? fm.contentsOfDirectory(atPath: userRoot) {
            for container in containers {
                let base = userRoot + "/" + container
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: base, isDirectory: &isDir), isDir.boolValue else { continue }
                let inner = subBundles(in: base, suffix: ".app")
                if inner.isEmpty {
                    if base.hasSuffix(".app") { add(base, .user) }
                } else {
                    for path in inner { add(path, .user) }
                }
            }
        }

        return output
    }

    static func subBundles(in directory: String, suffix: String) -> [String] {
        guard let items = try? fm.contentsOfDirectory(atPath: directory) else { return [] }
        var output: [String] = []
        for name in items where name.hasSuffix(suffix) {
            let full = directory + "/" + name
            var isDir: ObjCBool = false
            if fm.fileExists(atPath: full, isDirectory: &isDir), isDir.boolValue {
                output.append(full)
            }
        }
        return output.sorted()
    }

    /// 收集 bundle 内的嵌套可执行文件：App 扩展、Frameworks 里的 dylib / framework 主二进制。
    /// 原来只扫主二进制，注入到扩展或框架里的 tweak 会整条漏掉。
    static func nestedBinaries(bundlePath: String) -> [(label: String, path: String)] {
        var output: [(label: String, path: String)] = []
        var seen = Set<String>()

        func add(_ label: String, _ path: String) {
            guard !seen.contains(path), fm.fileExists(atPath: path) else { return }
            seen.insert(path)
            output.append((label, path))
        }

        // 1. 扩展 PlugIns/*.appex/<CFBundleExecutable>
        for extensionPath in subBundles(in: bundlePath + "/PlugIns", suffix: ".appex") {
            let extName = (extensionPath as NSString).lastPathComponent
            if let plist = readPlist(extensionPath + "/Info.plist"),
               let executable = plist["CFBundleExecutable"] as? String, !executable.isEmpty {
                add(extName, extensionPath + "/" + executable)
            }
        }

        // 2. Frameworks/ 下的 dylib 与 framework 主二进制
        let frameworks = bundlePath + "/Frameworks"
        guard let items = try? fm.contentsOfDirectory(atPath: frameworks) else { return output }
        for name in items.sorted() {
            let full = frameworks + "/" + name
            if name.hasSuffix(".dylib") {
                add(name, full)
            } else if name.hasSuffix(".framework") {
                let binaryName = (name as NSString).deletingPathExtension
                add(name, full + "/" + binaryName)
                if let subs = try? fm.contentsOfDirectory(atPath: full) {
                    for sub in subs where sub.hasSuffix(".dylib") {
                        add(name + "/" + sub, full + "/" + sub)
                    }
                }
            }
        }
        return output
    }

    // MARK: 数据容器映射

    static func buildContainerMap() -> [String: String] {
        var map: [String: String] = [:]
        let root = "/var/mobile/Containers/Data/Application"
        guard let dirs = try? fm.contentsOfDirectory(atPath: root) else { return map }
        for dir in dirs {
            let base = root + "/" + dir
            let meta = base + "/.com.apple.mobile_container_manager.metadata.plist"
            guard let plist = readPlist(meta) else { continue }
            guard let identifier = plist["MCMMetadataIdentifier"] as? String, !identifier.isEmpty else { continue }
            map[identifier] = base
        }
        return map
    }

    // MARK: 解析单个安装包

    static func parseApp(bundlePath: String,
                         kind: AppKind,
                         containerMap: [String: String],
                         options: ScanOptions) -> AppRecord? {

        guard let plist = readPlist(bundlePath + "/Info.plist") else { return nil }
        guard let bundleID = plist["CFBundleIdentifier"] as? String, !bundleID.isEmpty else { return nil }

        var record = AppRecord()
        record.id = bundlePath
        record.bundlePath = bundlePath
        record.bundleID = bundleID
        record.kind = kind

        let folderName = ((bundlePath as NSString).lastPathComponent as NSString).deletingPathExtension
        let bundleName = plist["CFBundleName"] as? String ?? ""
        let displayName = plist["CFBundleDisplayName"] as? String ?? ""
        record.name = !displayName.isEmpty ? displayName : (!bundleName.isEmpty ? bundleName : folderName)
        record.displayName = record.name

        record.version = plist["CFBundleShortVersionString"] as? String ?? "-"
        record.build = plist["CFBundleVersion"] as? String ?? "-"
        record.minimumOS = (plist["MinimumOSVersion"] as? String)
            ?? (plist["LSMinimumSystemVersion"] as? String)
            ?? "-"
        record.executable = plist["CFBundleExecutable"] as? String ?? folderName
        record.containerPath = containerMap[bundleID]
        record.iconPath = findIcon(bundlePath: bundlePath, plist: plist)

        // 安装时间
        if let attrs = try? fm.attributesOfItem(atPath: bundlePath) {
            if let date = attrs[.creationDate] as? Date {
                record.installDate = date
            } else if let date = attrs[.modificationDate] as? Date {
                record.installDate = date
            }
        }

        // 体积
        if options.computeSize {
            record.sizeBytes = directorySize(bundlePath)
        }

        // URL Schemes
        if let types = plist["CFBundleURLTypes"] as? [[String: Any]] {
            for type in types {
                if let schemes = type["CFBundleURLSchemes"] as? [String] {
                    record.urlSchemes.append(contentsOf: schemes)
                }
            }
        }

        // 隐私权限描述
        for key in plist.keys where key.hasSuffix("UsageDescription") {
            record.privacyKeys.append(key)
        }
        record.privacyKeys.sort()

        // Mach-O / 注入库 / 签名
        if options.readMachO {
            let executablePath = bundlePath + "/" + record.executable
            if let macho = MachO.parse(path: executablePath) {
                record.architectures = macho.architectures
                record.encrypted = macho.encrypted
                record.binaryUUID = macho.uuid
                record.buildSDK = macho.sdkVersion
                record.binaryMinOS = macho.minOSVersion
                if macho.codeSigSize > 0, options.readEntitlements,
                   let signature = CodeSign.parse(path: executablePath,
                                                  offset: macho.codeSigOffset,
                                                  size: macho.codeSigSize) {
                    record.sign = signature
                }
                for library in macho.dylibs {
                    if isInjectedLibrary(library) {
                        record.injectedLibs.append(library)
                    } else if isExternalLibrary(library) {
                        record.externalLibs.append(library)
                    }
                    // 声明了依赖但文件不在 → 这个 App 一启动就会 dyld 崩
                    if library.hasPrefix("@"),
                       isLibraryMissing(library, rpaths: macho.rpaths, bundlePath: bundlePath) {
                        record.missingLibs.append(library)
                    }
                }
            }

            // 嵌套二进制：扩展 / Frameworks 里被注入的 tweak 也不能漏
            var nestedHitLabels: [String] = []
            for nested in nestedBinaries(bundlePath: bundlePath) {
                guard let macho = MachO.parse(path: nested.path) else { continue }
                var hit = false
                for library in macho.dylibs {
                    if isInjectedLibrary(library) {
                        if !record.injectedLibs.contains(library) {
                            record.injectedLibs.append(library)
                        }
                        hit = true
                    } else if isExternalLibrary(library), !record.externalLibs.contains(library) {
                        record.externalLibs.append(library)
                    }
                }
                if hit, !nestedHitLabels.contains(nested.label) {
                    nestedHitLabels.append(nested.label)
                }
            }
            if !nestedHitLabels.isEmpty {
                record.notes.append("注入来自子包：" + nestedHitLabels.joined(separator: "、"))
            }
        }

        if fm.fileExists(atPath: bundlePath + "/SC_Info") {
            record.encrypted = true
            record.notes.append("存在 SC_Info，App Store FairPlay 加密")
        }
        if let codeSigs = try? fm.contentsOfDirectory(atPath: bundlePath + "/_CodeSignature") {
            if !codeSigs.isEmpty { record.sign.hasSignature = true }
        }

        // App Groups
        if let groups = record.sign.entitlements["com.apple.security.application-groups"] as? [String] {
            record.appGroups = groups
        }

        // 扩展
        if options.includeExtensions {
            for extensionPath in subBundles(in: bundlePath + "/PlugIns", suffix: ".appex") {
                var item = AppExtension()
                item.path = extensionPath
                if let extPlist = readPlist(extensionPath + "/Info.plist") {
                    item.bundleID = extPlist["CFBundleIdentifier"] as? String ?? ""
                    let extDisplay = extPlist["CFBundleDisplayName"] as? String ?? ""
                    let extName = extPlist["CFBundleName"] as? String ?? ""
                    item.name = !extDisplay.isEmpty ? extDisplay : (!extName.isEmpty ? extName : ((extensionPath as NSString).lastPathComponent))
                }
                if !item.bundleID.isEmpty { record.extensions.append(item) }
            }
        }

        // 描述文件（有 embedded.mobileprovision 才解析，App Store 包没有）
        if let provision = Provision.parse(bundlePath: bundlePath) {
            record.provision = provision
            if provision.isExpired {
                record.notes.append("描述文件已于 \(humanDate(provision.expirationDate)) 过期，当前渠道无法重新安装")
            } else if let days = provision.daysRemaining, days >= 0, days <= 14 {
                record.notes.append("描述文件 \(days) 天后过期")
            }
        }

        // 来源判定
        record.origin = originLabel(kind: kind, record: record, bundlePath: bundlePath)

        // 原始 Info.plist
        if let data = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0),
           data.count < 512 * 1024,
           let text = String(data: data, encoding: .utf8) {
            record.infoPlistXML = text
        }

        return record
    }

    // MARK: 辅助

    static func readPlist(_ path: String) -> [String: Any]? {
        guard let data = fm.contents(atPath: path) else { return nil }
        guard let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) else { return nil }
        return object as? [String: Any]
    }

    static func directorySize(_ path: String) -> Int64 {
        var total: Int64 = 0
        let keys: [URLResourceKey] = [.fileSizeKey, .isRegularFileKey, .totalFileAllocatedSizeKey]
        let url = URL(fileURLWithPath: path)
        guard let enumerator = fm.enumerator(at: url,
                                             includingPropertiesForKeys: keys,
                                             options: [.skipsHiddenFiles],
                                             errorHandler: nil) else { return 0 }
        for case let fileURL as URL in enumerator {
            guard let values = try? fileURL.resourceValues(forKeys: Set(keys)) else { continue }
            if values.isRegularFile == true {
                total += Int64(values.fileSize ?? 0)
            }
        }
        return total
    }

    static func findIcon(bundlePath: String, plist: [String: Any]) -> String? {
        var names: [String] = []
        if let icons = plist["CFBundleIcons"] as? [String: Any],
           let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
           let files = primary["CFBundleIconFiles"] as? [String] {
            names.append(contentsOf: files)
        }
        if let files = plist["CFBundleIconFiles"] as? [String] {
            names.append(contentsOf: files)
        }
        if let file = plist["CFBundleIconFile"] as? String {
            names.append(file)
        }
        names.append(contentsOf: ["AppIcon60x60", "AppIcon76x76", "Icon-60", "Icon", "AppIcon"])

        let suffixes = ["@3x.png", "@2x.png", ".png"]
        for name in names {
            var base = name
            if base.hasSuffix(".png") { base = String(base.dropLast(4)) }
            if base.isEmpty { continue }
            for suffix in suffixes {
                let candidate = bundlePath + "/" + base + suffix
                guard fm.fileExists(atPath: candidate) else { continue }
                if let image = UIImage(contentsOfFile: candidate), image.size.width >= 40 {
                    return candidate
                }
            }
        }
        return nil
    }

    /// 强标记：词本身足够独特，只要出现在路径里就算命中
    /// （越狱根目录、注入框架的固定安装位置）
    static let strongInjectionMarkers: [String] = [
        "/var/jb/",
        ".jbroot",
        "/library/mobilesubstrate/dynamiclibraries/",
        "tweakinject",
        "mobilesubstrate",
        "libsubstrate",
        "libhooker",
        "ellekit",
        "preferenceloader",
        "rocketbootstrap",
        "libkrw",
        "libcephei"
    ]

    /// 弱标记：名字太普通，必须整个文件名精确命中才算
    /// 之前用 contains("applist") / contains("flex") 会把自带同名类库的正常 App 误标红
    static let weakInjectionNames: Set<String> = [
        "substrate.dylib",
        "libapplist.dylib",
        "libflex.dylib",
        "libcolorpicker.dylib",
        "libpassby.dylib",
        "cycript"
    ]

    static func isInjectedLibrary(_ path: String) -> Bool {
        let lower = path.lowercased()
        guard !lower.isEmpty else { return false }

        for marker in strongInjectionMarkers where lower.contains(marker) {
            return true
        }

        let fileName = (lower as NSString).lastPathComponent
        if weakInjectionNames.contains(fileName) { return true }

        return false
    }

    /// 展开 @rpath / @executable_path / @loader_path，返回实际存在的绝对路径
    static func resolveLibrary(_ library: String,
                               rpaths: [String],
                               bundlePath: String) -> String? {
        func expand(_ path: String) -> String {
            path
                .replacingOccurrences(of: "@executable_path", with: bundlePath)
                .replacingOccurrences(of: "@loader_path", with: bundlePath)
        }

        if library.hasPrefix("@rpath/") {
            let rest = String(library.dropFirst("@rpath/".count))
            for rpath in rpaths {
                let candidate = expand(rpath) + "/" + rest
                if fm.fileExists(atPath: candidate) { return candidate }
            }
            return nil
        }
        if library.hasPrefix("@") {
            let expanded = expand(library)
            return fm.fileExists(atPath: expanded) ? expanded : nil
        }
        return fm.fileExists(atPath: library) ? library : nil
    }

    /// 判断一个 @ 开头的依赖是不是真的缺文件。
    /// 系统 Swift 运行时不在 App 包里，必须排除，否则满屏误报。
    static func isLibraryMissing(_ library: String,
                                 rpaths: [String],
                                 bundlePath: String) -> Bool {
        if resolveLibrary(library, rpaths: rpaths, bundlePath: bundlePath) != nil { return false }

        let name = (library as NSString).lastPathComponent
        if name.isEmpty { return false }
        if name.hasPrefix("libswift") || name.hasPrefix("libSystem") || name.hasPrefix("libc++") {
            return false
        }
        let systemCandidates = [
            "/usr/lib/swift/" + name,
            "/usr/lib/" + name,
            "/System/Library/Frameworks/" + name
        ]
        for candidate in systemCandidates where fm.fileExists(atPath: candidate) {
            return false
        }
        return true
    }

    static func isExternalLibrary(_ path: String) -> Bool {
        if path.hasPrefix("@") { return false }
        if path.hasPrefix("/usr/lib/") { return false }
        if path.hasPrefix("/System/") { return false }
        if path.hasPrefix("/AppleInternal/") { return false }
        return path.hasPrefix("/")
    }

    static func originLabel(kind: AppKind, record: AppRecord, bundlePath: String) -> String {
        if kind == .system || bundlePath.hasPrefix("/System/") { return "苹果系统" }
        if record.provision.exists {
            if record.provision.provisionsAllDevices { return "企业签（In-House）" }
            if record.provision.provisionedDeviceCount > 0 { return "描述文件（Ad Hoc / 开发）" }
        }
        if fm.fileExists(atPath: bundlePath + "/SC_Info") { return "App Store" }
        if fm.fileExists(atPath: bundlePath + "/embedded.mobileprovision") {
            return record.sign.isAdhoc ? "企业签名 · 侧载" : "企业 / 开发签名"
        }
        if record.sign.isAdhoc { return "TrollStore / 侧载" }
        if !record.sign.teamID.isEmpty { return "App Store" }
        if !record.sign.hasSignature { return "未签名" }
        return "侧载"
    }
}

// MARK: - 环境探针

struct EnvironmentInfo {
    var uid: UInt32 = 0
    var canReadBundleRoot: Bool = false
    var canReadApplications: Bool = false
    var canReadContainers: Bool = false
    var jailbreakPaths: [String] = []
    var trollStoreDetected: Bool = false
    var deviceModel: String = ""
    var systemVersion: String = ""
    var appPath: String = ""
    var entitlementKeys: [String] = []
    var hasNoSandbox: Bool = false
    var hasPlatformApp: Bool = false
}

enum EnvironmentProbe {

    static func probe() -> EnvironmentInfo {
        let fm = FileManager.default
        var info = EnvironmentInfo()
        info.uid = getuid()

        info.canReadBundleRoot = ((try? fm.contentsOfDirectory(atPath: "/var/containers/Bundle/Application")) != nil)
        info.canReadApplications = ((try? fm.contentsOfDirectory(atPath: "/Applications")) != nil)
        info.canReadContainers = ((try? fm.contentsOfDirectory(atPath: "/var/mobile/Containers/Data/Application")) != nil)

        let jailbreakCandidates = [
            "/var/jb",
            "/usr/lib/libsubstrate.dylib",
            "/usr/lib/TweakInject",
            "/Library/MobileSubstrate/DynamicLibraries",
            "/bin/bash",
            "/usr/bin/ssh",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/var/lib/dpkg",
            "/usr/lib/libhooker.dylib",
            "/usr/lib/libellekit.dylib"
        ]
        info.jailbreakPaths = jailbreakCandidates.filter { fm.fileExists(atPath: $0) }

        info.trollStoreDetected = fm.fileExists(atPath: "/var/mobile/Library/TrollStore")
            || fm.fileExists(atPath: "/var/mobile/Library/TrollStore/persistenceHelper_Embedded")

        info.deviceModel = UIDevice.current.model
        info.systemVersion = UIDevice.current.systemVersion
        info.appPath = Bundle.main.bundlePath

        if let executable = Bundle.main.executablePath,
           let macho = MachO.parse(path: executable),
           macho.codeSigSize > 0,
           let signature = CodeSign.parse(path: executable,
                                          offset: macho.codeSigOffset,
                                          size: macho.codeSigSize) {
            info.entitlementKeys = signature.entitlements.keys.sorted()
            info.hasNoSandbox = signature.entitlements["com.apple.private.security.no-sandbox"] != nil
            info.hasPlatformApp = signature.entitlements["platform-application"] != nil
        }

        return info
    }
}
