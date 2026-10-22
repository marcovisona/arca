import Foundation
import Testing
@testable import ArcaKit

@Suite struct ZipReadTests {
    @Test func readsWinZipAESFromPyzipper() async throws {
        let archive = try await Archive.open(Fixtures.url("aes256.zip"), passwords: ["secret"])
        let snapshot = try await archive.snapshot()
        #expect(snapshot.isEncrypted)
        #expect(Set(snapshot.entries.map(\.path)) == ["hello.txt", "docs/notes.md", "docs/data.bin"])
        let hello = try await archive.data(for: "hello.txt")
        #expect(String(decoding: hello, as: UTF8.self) == "Hello, Arca!\n")
        let notes = try await archive.data(for: "docs/notes.md")
        #expect(notes.count == 8 + 27 * 500)
        #expect(try await archive.data(for: "docs/data.bin").count == 50000)
    }

    @Test func passwordErrors() async throws {
        let locked = try await Archive.open(Fixtures.url("aes256.zip"))
        await #expect(throws: ArchiveError.passwordRequired(entry: "hello.txt")) {
            try await locked.data(for: "hello.txt")
        }
        try await locked.addPassword("nope")
        await #expect(throws: ArchiveError.wrongPassword(entry: "hello.txt")) {
            try await locked.data(for: "hello.txt")
        }
        try await locked.addPassword("secret")
        #expect(try await locked.data(for: "hello.txt").count == 13)
    }

    @Test func readsZipCrypto() async throws {
        let archive = try await Archive.open(Fixtures.url("zipcrypto.zip"), passwords: ["secret"])
        let data = try await archive.data(for: "docs/notes.md")
        #expect(String(decoding: data.prefix(7), as: UTF8.self) == "# Notes")
        #expect(try await archive.snapshot().notes.contains { $0.contains("ZipCrypto") })
    }

    @Test func readsZip64AndUnicodeNames() async throws {
        let archive = try await Archive.open(Fixtures.url("zip64.zip"))
        let snapshot = try await archive.snapshot()
        #expect(snapshot.entries.map(\.path).contains("città/è.txt"))
        #expect(try await archive.data(for: "big/notes.md").count == 13508)
        #expect(snapshot.tree.node("città")?.isDirectory == true)
    }

    @Test func extractionRefusesPathTraversal() async throws {
        let s = try Scratch()
        let zip = s.path("evil.zip")
        try Data(handcraftedZip([("ok.txt", Array("fine".utf8)), ("a/../../evil.txt", Array("pwned".utf8))])).write(to: zip)
        let archive = try await Archive.open(zip, journal: s.journal)
        let out = s.path("out")
        await #expect(throws: ArchiveError.self) {
            try await archive.extract([], to: out)
        }
        #expect(!FileManager.default.fileExists(atPath: s.url.appendingPathComponent("evil.txt").path))
    }
}

@Suite struct ZipEditTests {
    private func makeArchive(_ s: Scratch) async throws -> Archive {
        let a = try s.file("src/a.txt", String(repeating: "alpha ", count: 2000))
        let b = try s.file("src/folder/b.txt", "bravo")
        let c = try s.file("src/folder/deep/c.bin", bytes: 300_000)
        let archive = try await Archive.create(s.path("test.zip"), format: .zip, journal: s.journal)
        _ = try await archive.apply([.add(source: a, at: "a.txt"), .add(source: b, at: "folder/b.txt"),
                                     .add(source: c, at: "folder/deep/c.bin")])
        return archive
    }

    @Test func editsLeaveUntouchedBytesInPlace() async throws {
        let s = try Scratch()
        let archive = try await makeArchive(s)
        let before = try Data(contentsOf: s.path("test.zip"))
        let zip = try ZipArchive(path: s.path("test.zip").path, journal: s.journal)
        let cdStart = Int(zip.centralDirectoryStart)

        let n = try s.file("n.txt", "november")
        _ = try await archive.apply([.add(source: n, at: "folder/n.txt"), .delete("a.txt")])
        let after = try Data(contentsOf: s.path("test.zip"))
        // Everything before the old central directory is byte-identical.
        #expect(after.prefix(cdStart) == before.prefix(cdStart))
        #expect(String(decoding: try await archive.data(for: "folder/n.txt"), as: UTF8.self) == "november")
        #expect(try await archive.snapshot().entries.map(\.path).contains("a.txt") == false)
        if let result = runTool("unzip", ["-tq", s.path("test.zip").path]) { #expect(result.status == 0, "\(result.output)") }
    }

    @Test func renameFolderCopiesRawBytes() async throws {
        let s = try Scratch()
        let archive = try await makeArchive(s)
        let original = try await archive.data(for: "folder/deep/c.bin")
        let snapshot = try await archive.apply([.rename(from: "folder", to: "renamed/inner")])
        #expect(Set(snapshot.entries.map(\.path)) == ["a.txt", "renamed/inner/b.txt", "renamed/inner/deep/c.bin"])
        #expect(try await archive.data(for: "renamed/inner/deep/c.bin") == original)
        if let result = runTool("unzip", ["-tq", s.path("test.zip").path]) { #expect(result.status == 0, "\(result.output)") }
    }

    @Test func replaceAndCompact() async throws {
        let s = try Scratch()
        let archive = try await makeArchive(s)
        for i in 0..<3 {
            _ = try await archive.apply([.addData(Data("version \(i)".utf8), at: "a.txt"),
                                         .add(source: try s.file("c\(i).bin", bytes: 100_000, seed: UInt64(i)),
                                              at: "folder/deep/c.bin")])
        }
        let bloated = try await archive.snapshot().statistics
        #expect(bloated.reclaimableBytes > 0)
        let compacted = try await archive.compact()
        #expect(compacted.statistics.archiveSize < bloated.archiveSize)
        #expect(compacted.statistics.reclaimableBytes == 0)
        #expect(String(decoding: try await archive.data(for: "a.txt"), as: UTF8.self) == "version 2")
        #expect(try await archive.data(for: "folder/deep/c.bin") == (try Data(contentsOf: s.path("c2.bin"))))
    }

    @Test func aesRoundTripAndInterop() async throws {
        let s = try Scratch()
        let archive = try await Archive.create(s.path("secret.zip"), format: .zip, journal: s.journal)
        let options = WriteOptions(encryption: .aes256(password: "pa55"))
        let big = try s.file("big.bin", bytes: 200_000, seed: 9)
        _ = try await archive.apply([.addData(Data(String(repeating: "x", count: 10_000).utf8), at: "x.txt"),
                                     .add(source: big, at: "big.bin")], options: options)
        let reopened = try await Archive.open(s.path("secret.zip"), journal: s.journal)
        await #expect(throws: ArchiveError.passwordRequired(entry: "x.txt")) { try await reopened.data(for: "x.txt") }
        try await reopened.addPassword("pa55")
        #expect(try await reopened.data(for: "x.txt").count == 10_000)
        #expect(try await reopened.data(for: "big.bin") == (try Data(contentsOf: big)))
        // Tamper with ciphertext: HMAC must catch it.
        let file = try RandomAccessFile(path: s.path("secret.zip").path, writable: true)
        let zip = try ZipArchive(path: s.path("secret.zip").path, journal: s.journal)
        let target = zip.records.first { $0.path == "big.bin" }!
        try file.write([0xFF], at: target.localHeaderOffset + 30 + 7 + 50 + 1000)
        let tampered = try await Archive.open(s.path("secret.zip"), passwords: ["pa55"], journal: s.journal)
        await #expect(throws: ArchiveError.checksumMismatch(entry: "big.bin")) { try await tampered.data(for: "big.bin") }
    }

    @Test func failedCommitRollsBackToIdenticalBytes() throws {
        let s = try Scratch()
        let path = s.path("crash.zip").path
        let zip = try ZipArchive.create(path: path, journal: s.journal)
        try zip.apply([.addData(Data("one".utf8), at: "one.txt"), .addData(Data("two".utf8), at: "two.txt")],
                      options: .default, progress: nil)
        let before = try Data(contentsOf: URL(fileURLWithPath: path))
        for stage in ["entry", "centralDirectory", "sync"] {
            zip.faultInjector = { if $0 == stage { throw ArchiveError.cancelled } }
            #expect(throws: ArchiveError.cancelled) {
                try zip.apply([.addData(Data(repeating: 7, count: 100_000), at: "three.bin"), .delete("one.txt")],
                              options: .default, progress: nil)
            }
            #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == before, "stage \(stage)")
        }
        zip.faultInjector = nil
        try zip.apply([.delete("one.txt")], options: .default, progress: nil)
        #expect(zip.entries.map(\.path) == ["two.txt"])
    }

    @Test func journalRecoversAfterSimulatedCrash() throws {
        let s = try Scratch()
        let path = s.path("power-loss.zip").path
        let zip = try ZipArchive.create(path: path, journal: s.journal)
        try zip.apply([.addData(Data("keep me".utf8), at: "keep.txt")], options: .default, progress: nil)
        let before = try Data(contentsOf: URL(fileURLWithPath: path))

        // Simulate a crash mid-commit: journal written, tail half-overwritten.
        let file = try RandomAccessFile(path: path, writable: true)
        let cd = zip.centralDirectoryStart
        let tail = try file.readExactly(at: cd, count: Int(try file.size() - cd))
        _ = try s.journal.begin(archivePath: path, originalSize: try file.size(), tailOffset: cd, tail: tail)
        try file.write([UInt8](repeating: 0xAB, count: 5000), at: cd)

        let recovered = try ZipArchive(path: path, journal: s.journal)
        #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == before)
        #expect(recovered.entries.map(\.path) == ["keep.txt"])
    }

    @Test func cancellationRollsBack() async throws {
        let s = try Scratch()
        let archive = try await makeArchive(s)
        let before = try Data(contentsOf: s.path("test.zip"))
        let progress = ProgressReporter()
        progress.cancel()
        let big = try s.file("huge.bin", bytes: 3_000_000)
        await #expect(throws: ArchiveError.cancelled) {
            try await archive.apply([.add(source: big, at: "huge.bin")], progress: progress)
        }
        #expect(try Data(contentsOf: s.path("test.zip")) == before)
    }

    @Test func detectsExternalModification() async throws {
        let s = try Scratch()
        let archive = try await makeArchive(s)
        let handle = try FileHandle(forWritingTo: s.path("test.zip"))
        try handle.seekToEnd()
        try handle.write(contentsOf: Data([0]))
        try handle.close()
        await #expect(throws: ArchiveError.modifiedExternally) {
            try await archive.apply([.delete("a.txt")])
        }
    }

    @Test func extractFolderWithConflicts() async throws {
        let s = try Scratch()
        let archive = try await makeArchive(s)
        let out = s.path("out")
        let first = try await archive.extract(["folder"], to: out)
        #expect(first.map(\.lastPathComponent) == ["folder"])
        let second = try await archive.extract(["folder"], to: out, conflict: .keepBoth)
        #expect(second.map(\.lastPathComponent) == ["folder 2"])
        let inner = try await archive.extract(["folder/deep"], relativeTo: "folder", to: out)
        #expect(inner.map(\.lastPathComponent) == ["deep"])
        #expect(FileManager.default.fileExists(atPath: out.appendingPathComponent("folder 2/deep/c.bin").path))
    }

    @Test func addingFolderRecursivelySkipsMacMetadata() async throws {
        let s = try Scratch()
        _ = try s.file("tree/x.txt", "x")
        _ = try s.file("tree/.DS_Store", "junk")
        _ = try s.file("tree/sub/y.txt", "y")
        let archive = try await Archive.compress([s.path("tree")], into: s.path("t.zip"), format: .zip)
        let paths = Set(try await archive.snapshot().entries.map(\.path))
        #expect(paths == ["tree", "tree/x.txt", "tree/sub", "tree/sub/y.txt"])
    }

    @Test func preservesUnicodeFilenamesAcrossListingExtractionAndRename() async throws {
        let s = try Scratch()
        let archive = try await Archive.create(s.path("unicode.zip"), format: .zip, journal: s.journal)
        let names = ["café.txt", "🙂.txt", "name with spaces.txt", "東京.txt", "e\u{301}.txt"]
        let changes = names.map { name in
            ArchiveChange.addData(Data("contents:\(name)".utf8), at: name)
        }
        _ = try await archive.apply(changes)

        let listed = try await archive.snapshot().entries.map(\.path)
        for name in names {
            let expectedScalars = name.unicodeScalars.map(\.value)
            #expect(listed.contains { $0.unicodeScalars.map(\.value) == expectedScalars })
            #expect(String(decoding: try await archive.data(for: name), as: UTF8.self) == "contents:\(name)")
        }

        let out = s.path("extracted")
        _ = try await archive.extract([], to: out)
        let extractedFiles = try FileManager.default.contentsOfDirectory(at: out, includingPropertiesForKeys: nil)
        #expect(Set(try extractedFiles.map { String(decoding: try Data(contentsOf: $0), as: UTF8.self) }) ==
                Set(names.map { "contents:\($0)" }))

        _ = try await archive.apply([.rename(from: "東京.txt", to: "東京-renamed.txt")])
        let renamed = try await archive.snapshot().entries.map(\.path)
        #expect(renamed.contains("東京-renamed.txt"))
        #expect(!renamed.contains("東京.txt"))
        #expect(String(decoding: try await archive.data(for: "東京-renamed.txt"), as: UTF8.self) == "contents:東京.txt")
    }

}
