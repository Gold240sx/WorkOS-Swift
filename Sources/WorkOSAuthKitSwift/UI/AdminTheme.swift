import SwiftUI
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// Theme configuration for admin UI components.
public struct AdminTheme: Sendable {
    public var primaryColor: Color
    public var secondaryColor: Color
    public var destructiveColor: Color
    public var backgroundColor: Color
    public var surfaceColor: Color
    public var textColor: Color
    public var secondaryTextColor: Color
    public var cornerRadius: CGFloat
    public var spacing: CGFloat

    /// Default surface color that adapts to platform
    private static var defaultSurfaceColor: Color {
        #if canImport(UIKit)
        return Color(UIColor.systemBackground)
        #elseif canImport(AppKit)
        return Color(NSColor.windowBackgroundColor)
        #else
        return Color.white
        #endif
    }

    public init(
        primaryColor: Color = .accentColor,
        secondaryColor: Color = .gray,
        destructiveColor: Color = .red,
        backgroundColor: Color = .clear,
        surfaceColor: Color? = nil,
        textColor: Color = .primary,
        secondaryTextColor: Color = .secondary,
        cornerRadius: CGFloat = 12,
        spacing: CGFloat = 16
    ) {
        self.primaryColor = primaryColor
        self.secondaryColor = secondaryColor
        self.destructiveColor = destructiveColor
        self.backgroundColor = backgroundColor
        self.surfaceColor = surfaceColor ?? Self.defaultSurfaceColor
        self.textColor = textColor
        self.secondaryTextColor = secondaryTextColor
        self.cornerRadius = cornerRadius
        self.spacing = spacing
    }
}

// MARK: - Environment Key

private struct AdminThemeKey: EnvironmentKey {
    static let defaultValue = AdminTheme()
}

extension EnvironmentValues {
    public var adminTheme: AdminTheme {
        get { self[AdminThemeKey.self] }
        set { self[AdminThemeKey.self] = newValue }
    }
}

// MARK: - View Modifier

extension View {
    /// Apply the admin theme to this view hierarchy.
    public func adminTheme(_ theme: AdminTheme) -> some View {
        environment(\.adminTheme, theme)
    }
}

// MARK: - Themed Components

extension AdminTheme {
    /// Create a primary button style.
    public var primaryButtonStyle: some ButtonStyle {
        PrimaryButtonStyle(theme: self)
    }

    /// Create a secondary button style.
    public var secondaryButtonStyle: some ButtonStyle {
        SecondaryButtonStyle(theme: self)
    }

    /// Create a destructive button style.
    public var destructiveButtonStyle: some ButtonStyle {
        DestructiveButtonStyle(theme: self)
    }
}

// MARK: - Button Styles

struct PrimaryButtonStyle: ButtonStyle {
    let theme: AdminTheme

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, theme.spacing)
            .padding(.vertical, theme.spacing / 2)
            .background(theme.primaryColor.opacity(configuration.isPressed ? 0.8 : 1))
            .foregroundColor(.white)
            .cornerRadius(theme.cornerRadius)
    }
}

struct SecondaryButtonStyle: ButtonStyle {
    let theme: AdminTheme

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, theme.spacing)
            .padding(.vertical, theme.spacing / 2)
            .background(theme.secondaryColor.opacity(configuration.isPressed ? 0.2 : 0.1))
            .foregroundColor(theme.primaryColor)
            .cornerRadius(theme.cornerRadius)
    }
}

struct DestructiveButtonStyle: ButtonStyle {
    let theme: AdminTheme

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, theme.spacing)
            .padding(.vertical, theme.spacing / 2)
            .background(theme.destructiveColor.opacity(configuration.isPressed ? 0.8 : 1))
            .foregroundColor(.white)
            .cornerRadius(theme.cornerRadius)
    }
}
