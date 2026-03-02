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
IDENTITY="${CODESIGN_IDENTITY:?Set CODESIGN_IDENTITY in .env or as env var}"
BUNDLE_ID="${BUNDLE_ID:-com.example.plc-touch}"
TEAM_ID="${TEAM_ID:-XXXXXXXXXX}"

KEYCHAIN_ACCESS_GROUP="${TEAM_ID}.${BUNDLE_ID}" cargo build --release

# Create .app bundle
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"

cp target/release/plc-touch "$APP/Contents/MacOS/plc-touch"

# Copy provisioning profile if it exists
if [ -f embedded.provisionprofile ]; then
    cp embedded.provisionprofile "$APP/Contents/embedded.provisionprofile"
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

# Generate entitlements from env vars
ENTITLEMENTS_FILE=$(mktemp)
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

codesign --force --sign "$IDENTITY" --entitlements "$ENTITLEMENTS_FILE" "$APP"
rm -f "$ENTITLEMENTS_FILE"

echo "✓ Built and signed $APP"
echo "  Run with: $APP/Contents/MacOS/plc-touch"
