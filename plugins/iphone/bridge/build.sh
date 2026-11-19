#!/bin/sh
# Build bin/Shadetree iPhone Bridge.app (universal arm64 + x86_64) from bridge/.
#
# The built bundle is committed: plugin installs copy files and never run a build.
#
# FDA grants are tied to the code signature, so rebuilding changes what users
# granted:
#   - Ad-hoc signing (default): the grant is tied to this exact binary. Any rebuild
#     that changes the bytes makes every user grant FDA again. Only rebuild when the
#     bridge actually has to change, and bump CFBundleVersion in Info.plist.
#   - Developer ID (BRIDGE_SIGN_IDENTITY="Developer ID Application: ..."): the grant
#     is tied to the bundle ID + team, so rebuilds keep working. Add
#     BRIDGE_NOTARY_PROFILE=<notarytool keychain profile> to notarize and staple.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
app="$here/../bin/Shadetree iPhone Bridge.app"
exe_name=shadetree-iphone-bridge
bundle_id=io.github.ajelinek.shadetree-ai-plugins.iphone-bridge

rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp "$here/Info.plist" "$app/Contents/Info.plist"

xcrun clang -O2 -Wall -Wextra -Werror \
  -arch arm64 -arch x86_64 -mmacosx-version-min=12.0 \
  -o "$app/Contents/MacOS/$exe_name" "$here/iphone_bridge.c"

if [ -n "${BRIDGE_SIGN_IDENTITY:-}" ]; then
  codesign --force --options runtime --timestamp \
    --identifier "$bundle_id" --sign "$BRIDGE_SIGN_IDENTITY" "$app"
  if [ -n "${BRIDGE_NOTARY_PROFILE:-}" ]; then
    zip_path=$(mktemp -d)/bridge.zip
    ditto -c -k --keepParent "$app" "$zip_path"
    xcrun notarytool submit "$zip_path" --keychain-profile "$BRIDGE_NOTARY_PROFILE" --wait
    xcrun stapler staple "$app"
  fi
else
  codesign --force --identifier "$bundle_id" --sign - "$app"
fi

codesign --verify --strict --verbose=1 "$app"
codesign -dv "$app" 2>&1 | grep -E '^(Identifier|CDHash|TeamIdentifier|Signature)'
