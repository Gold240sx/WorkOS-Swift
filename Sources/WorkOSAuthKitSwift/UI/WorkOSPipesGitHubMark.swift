import SwiftUI

/// GitHub mark used for WorkOS Pipes / GitHub integration UI (vector asset ships in this package).
public struct WorkOSPipesGitHubMark: View {
    public init() {}

    public var body: some View {
        Image("github-mark", bundle: .module)
            .resizable()
            .renderingMode(.template)
            .interpolation(.high)
            .antialiased(true)
    }
}
