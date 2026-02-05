import Foundation
import Network

/// Basic internet reachability monitor.
///
/// Uses NWPathMonitor to determine whether the device currently has a viable network path.
@MainActor
public final class NetworkMonitor: ObservableObject {
    @Published public private(set) var isOnline: Bool = true

    private let monitor: NWPathMonitor
    private let queue: DispatchQueue

    public init() {
        self.monitor = NWPathMonitor()
        self.queue = DispatchQueue(label: "WorkOSAuthKitSwift.NetworkMonitor")

        monitor.pathUpdateHandler = { [weak self] path in
            let online = (path.status == .satisfied)
            Task { @MainActor in
                self?.isOnline = online
            }
        }
        monitor.start(queue: queue)
    }

    deinit {
        monitor.cancel()
    }
}

