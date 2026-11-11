#!/usr/bin/env bash
# Renders the Nexus "Orbit N" icon from crates/nexus-app/assets/brand/*.svg.
#   out/nexus.png          256 px rounded tile (window icon, include_bytes! in main.rs)
#   out/nexus.ico          16/24/32 (small-size art) + 48/256 (full art), for build.rs
#   out/Nexus-AppIcon.png  1024 px opaque square for the iOS AppIcon set
# Runs inside a disposable Ubuntu container so nothing is installed on Windows:
#   docker run --rm -v "<repo>:/repo" -w /repo ubuntu:24.04 bash scripts/render-icons.sh
set -euo pipefail
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends librsvg2-bin imagemagick >/dev/null
src=crates/nexus-app/assets/brand
out=crates/nexus-app/assets/brand/out
mkdir -p "$out" /tmp/icons

# iOS: full bleed, no alpha (App Store icons must be opaque).
rsvg-convert -w 1024 -h 1024 "$src/nexus-icon.svg" -o /tmp/icons/full-1024.png
convert /tmp/icons/full-1024.png -background '#060A16' -alpha remove -alpha off "$out/Nexus-AppIcon.png"

# Windows large sizes: full art on a rounded tile (radius ~19.5% like the small art).
for s in 256 48; do
  rsvg-convert -w "$s" -h "$s" "$src/nexus-icon.svg" -o "/tmp/icons/full-$s.png"
  r=$(( s * 200 / 1024 ))
  convert -size "${s}x${s}" xc:none -fill white -draw "roundrectangle 0,0 $((s-1)),$((s-1)) $r,$r" "/tmp/icons/mask-$s.png"
  convert "/tmp/icons/full-$s.png" "/tmp/icons/mask-$s.png" -alpha off -compose CopyOpacity -composite "/tmp/icons/win-$s.png"
done
# Windows small sizes: heavier-stroke art drawn for 16-32 px.
for s in 32 24 16; do
  rsvg-convert -w "$s" -h "$s" "$src/nexus-icon-small.svg" -o "/tmp/icons/win-$s.png"
done
cp /tmp/icons/win-256.png "$out/nexus.png"
convert /tmp/icons/win-16.png /tmp/icons/win-24.png /tmp/icons/win-32.png /tmp/icons/win-48.png /tmp/icons/win-256.png "$out/nexus.ico"
# Preview strip for review (not shipped).
convert /tmp/icons/win-256.png \( /tmp/icons/win-48.png -background none -gravity center -extent 64x256 \) \
  \( /tmp/icons/win-32.png -background none -gravity center -extent 48x256 \) \
  \( /tmp/icons/win-24.png -background none -gravity center -extent 40x256 \) \
  \( /tmp/icons/win-16.png -background none -gravity center -extent 32x256 \) +append \
  -background '#EEF1F6' -alpha remove "$out/preview.png"
identify "$out/nexus.ico" "$out/nexus.png" "$out/Nexus-AppIcon.png"
