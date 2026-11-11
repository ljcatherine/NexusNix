# Nexus Desktop for Linux, built from this repository's Cargo workspace.
{
  lib,
  rustPlatform,
  makeWrapper,
  copyDesktopItems,
  makeDesktopItem,
  symlinkJoin,
  # runtime tools Nexus starts
  openssh,
  git,
  xdg-utils,
  dbus,
  desktop-file-utils,
  # libraries winit/wgpu load with dlopen at runtime
  libxkbcommon,
  vulkan-loader,
  libGL,
  wayland,
  libx11,
  libxcursor,
  libxi,
  libxrandr,
  libxcb,
  # fonts (Linux stand-ins for Segoe UI, Cascadia and Segoe Fluent Icons)
  inter,
  jetbrains-mono,
  nerd-fonts,
  noto-fonts-monochrome-emoji,
  dejavu_fonts,
}:

let
  cargoToml = lib.importTOML ../Cargo.toml;
  runtimeLibs = [
    libxkbcommon
    vulkan-loader
    libGL
    wayland
    libx11
    libxcursor
    libxi
    libxrandr
    libxcb
  ];
  fonts = symlinkJoin {
    name = "nexus-desktop-fonts";
    paths = [
      inter
      jetbrains-mono
      nerd-fonts.symbols-only
      noto-fonts-monochrome-emoji
      dejavu_fonts
    ];
  };
  tools = [
    openssh
    git
    xdg-utils
    dbus
    desktop-file-utils
  ];
in
rustPlatform.buildRustPackage {
  pname = "nexus-desktop";
  inherit (cargoToml.workspace.package) version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../.cargo
      ../crates
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  nativeBuildInputs = [
    makeWrapper
    copyDesktopItems
  ];

  # The SSH mock tests generate throwaway keys with ssh-keygen; the Git
  # tests drive the git CLI.
  nativeCheckInputs = [
    openssh
    git
  ];

  cargoBuildFlags = [ "--package" "nexus-app" "--package" "nexus-ro" ];
  # Run the whole workspace's tests, as `cargo test --workspace` does.
  cargoTestFlags = [ "--workspace" ];
  preCheck = ''
    export HOME=$TMPDIR
  '';

  desktopItems = [
    (makeDesktopItem {
      name = "nexus-desktop";
      desktopName = "Nexus";
      genericName = "IDE and infrastructure manager";
      comment = "Nexus Desktop: IDE, AI agents and server monitoring";
      exec = "nexus-desktop %u";
      icon = "nexus-desktop";
      categories = [ "Development" "IDE" "System" ];
      mimeTypes = [ "x-scheme-handler/com.ljcatherine.nexus" ];
      startupWMClass = "com.ljcatherine.NexusDesktop";
    })
  ];

  postInstall = ''
    install -Dm644 crates/nexus-app/assets/nexus.png $out/share/icons/hicolor/256x256/apps/nexus-desktop.png
    install -Dm644 crates/nexus-app/assets/brand/nexus-icon.svg $out/share/icons/hicolor/scalable/apps/nexus-desktop.svg
    wrapProgram $out/bin/NexusDesktop \
      --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath runtimeLibs} \
      --suffix PATH : ${lib.makeBinPath tools} \
      --set-default NEXUS_FONT_DIR ${fonts}/share/fonts \
      --set-default NEXUS_LAUNCHER $out/bin/nexus-desktop
    ln -s NexusDesktop $out/bin/nexus-desktop
  '';

  meta = {
    description = "Nexus Desktop: Rust IDE, AI agents and infrastructure manager (Linux port of Nexus Desktop for Windows)";
    homepage = "https://github.com/ljcatherine/NexusNix";
    license = lib.licenses.unfree;
    mainProgram = "nexus-desktop";
    platforms = lib.platforms.linux;
  };
}
