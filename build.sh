#!/bin/bash
set -e

APP="target/release/plc-touch.app"

# Load env vars from .env if it exists
if [ -f .env ]; then
    set -a
    source .env
    set +a
fi

# These must be set in .env or as env vars:
#   CODESIGN_IDENTITY="Apple Development: Your Name (XXXXXXXXXX)"
#   BUNDLE_ID="com.yourcompany.plc-touch"
#   TEAM_ID="XXXXXXXXXX"
#
# For release builds, also set:
#   DEVELOPER_ID="Developer ID Application: Your Name (XXXXXXXXXX)"
#   APPLE_ID="your@email.com"
#   NOTARIZE_PASSWORD="app-specific-password"
BUNDLE_ID="${BUNDLE_ID:-com.example.plc-touch}"
TEAM_ID="${TEAM_ID:-XXXXXXXXXX}"

MODE="${1:-dev}"

case "$MODE" in
    dev)
        IDENTITY="${CODESIGN_IDENTITY:?Set CODESIGN_IDENTITY in .env}"
        ;;
    release)
        IDENTITY="${DEVELOPER_ID:?Set DEVELOPER_ID in .env for release builds}"
        ;;
    *)
        echo "Usage: ./build.sh [dev|release]"
        echo "  dev     — Development build with provisioning profile (default)"
        echo "  release — Developer ID build with notarization for distribution"
        exit 1
        ;;
esac

echo "Building plc-touch ($MODE)..."

KEYCHAIN_ACCESS_GROUP="${TEAM_ID}.${BUNDLE_ID}" cargo build --release

# Create .app bundle
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"

cp target/release/plc-touch "$APP/Contents/MacOS/plc-touch"

# Embed provisioning profile
if [ "$MODE" = "dev" ] && [ -f embedded.provisionprofile ]; then
    cp embedded.provisionprofile "$APP/Contents/embedded.provisionprofile"
elif [ "$MODE" = "release" ] && [ -f release.provisionprofile ]; then
    cp release.provisionprofile "$APP/Contents/embedded.provisionprofile"
fi

cat > "$APP/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleName</key>
    <string>plc-touch</string>
    <key>CFBundleExecutable</key>
    <string>plc-touch</string>
    <key>CFBundleVersion</key>
    <string>0.1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
</dict>
</plist>
EOF

# Generate entitlements
ENTITLEMENTS_FILE=$(mktemp)
if [ "$MODE" = "release" ]; then
    # Developer ID with provisioning profile: includes application-identifier + keychain-access-groups
    cat > "$ENTITLEMENTS_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.application-identifier</key>
    <string>${TEAM_ID}.${BUNDLE_ID}</string>
    <key>keychain-access-groups</key>
    <array>
        <string>${TEAM_ID}.*</string>
    </array>
</dict>
</plist>
EOF
else
    # Dev: needs application-identifier for provisioning profile
    cat > "$ENTITLEMENTS_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.application-identifier</key>
    <string>${TEAM_ID}.${BUNDLE_ID}</string>
    <key>keychain-access-groups</key>
    <array>
        <string>${TEAM_ID}.*</string>
    </array>
</dict>
</plist>
EOF
fi

if [ "$MODE" = "release" ]; then
    # Release: Developer ID signing with hardened runtime (required for notarization)
    codesign --force --sign "$IDENTITY" \
        --options runtime \
        --timestamp \
        --entitlements "$ENTITLEMENTS_FILE" \
        "$APP"

    rm -f "$ENTITLEMENTS_FILE"

    echo "✓ Signed with Developer ID"

    # Create zip for notarization
    ZIP="target/release/plc-touch.zip"
    rm -f "$ZIP"
    ditto -c -k --keepParent "$APP" "$ZIP"

    echo "Submitting for notarization..."
    APPLE_ID_ARG="${APPLE_ID:?Set APPLE_ID in .env for notarization}"
    PASS_ARG="${NOTARIZE_PASSWORD:?Set NOTARIZE_PASSWORD in .env (app-specific password)}"

    xcrun notarytool submit "$ZIP" \
        --apple-id "$APPLE_ID_ARG" \
        --team-id "$TEAM_ID" \
        --password "$PASS_ARG" \
        --wait

    # Staple the notarization ticket to the app
    xcrun stapler staple "$APP"

    # Re-create zip with stapled app
    rm -f "$ZIP"
    ditto -c -k --keepParent "$APP" "$ZIP"

    echo ""
    echo "✓ Built, signed, notarized, and stapled"
    echo "  Distribute: $ZIP"
    echo "  Run with:   $APP/Contents/MacOS/plc-touch"
else
    # Dev: Apple Development signing
    codesign --force --sign "$IDENTITY" \
        --entitlements "$ENTITLEMENTS_FILE" \
        "$APP"

    rm -f "$ENTITLEMENTS_FILE"

    echo ""
    echo "✓ Built and signed (dev)"
    echo "  Run with: $APP/Contents/MacOS/plc-touch"
fi
