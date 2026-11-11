{
  description = "Nexus Desktop for Linux (NixOS): Rust IDE, AI agents and infrastructure manager";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      # Nexus Desktop is proprietary (LicenseRef-Proprietary), so its meta says
      # unfree. Allow exactly this package, nothing else, for this flake's outputs.
      allowNexus = pkg: nixpkgs.lib.getName pkg == "nexus-desktop";
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              config.allowUnfreePredicate = allowNexus;
            }
          )
        );
    in
    {
      packages = forAllSystems (pkgs: rec {
        nexus-desktop = pkgs.callPackage ./nix/package.nix { };
        default = nexus-desktop;
      });

      apps = forAllSystems (pkgs: rec {
        nexus-desktop = {
          type = "app";
          program = "${self.packages.${pkgs.stdenv.hostPlatform.system}.nexus-desktop}/bin/nexus-desktop";
          meta.description = "Run Nexus Desktop";
        };
        default = nexus-desktop;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.nexus-desktop ];
          packages = with pkgs; [
            rustc
            cargo
            clippy
            rustfmt
            rust-analyzer
            openssh
            git
            xdg-utils
          ];
          # winit and wgpu load these with dlopen.
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (
            with pkgs;
            [
              libxkbcommon
              vulkan-loader
              libGL
              wayland
              libx11
              libxcursor
              libxi
              libxrandr
              libxcb
            ]
          );
          NEXUS_FONT_DIR = pkgs.lib.makeSearchPath "share/fonts" (
            with pkgs;
            [
              inter
              jetbrains-mono
              nerd-fonts.symbols-only
              noto-fonts-monochrome-emoji
              dejavu_fonts
            ]
          );
        };
      });

      overlays.default = final: _prev: {
        nexus-desktop = final.callPackage ./nix/package.nix { };
      };

      nixosModules.default = import ./nix/module.nix self;
      nixosModules.nexus-desktop = self.nixosModules.default;

      checks = forAllSystems (pkgs: {
        package = self.packages.${pkgs.stdenv.hostPlatform.system}.nexus-desktop;
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
