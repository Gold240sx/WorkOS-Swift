//
//  WorkOSLogger.swift
//  WorkOSAuthKitSwift
//
//  Central logger for the library. Enabled/disabled via WorkOSConfiguration.debugLogging.
//  Call WorkOSLogger.configure(enabled:) once on AuthStore init.
//

import Foundation

enum WorkOSLogger {
    nonisolated(unsafe) private static var enabled = false

    /// Call this once when WorkOSConfiguration is applied.
    static func configure(enabled: Bool) {
        self.enabled = enabled
    }

    /// Emit a log line when debug logging is enabled.
    static func log(_ message: String) {
        guard enabled else { return }
        print(message)
    }
}
