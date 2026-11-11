# NixOS module: `programs.nexus-desktop.enable = true;`
self:
{ config, lib, pkgs, ... }:

let
  cfg = config.programs.nexus-desktop;
  scheme = "x-scheme-handler/com.ljcatherine.nexus";
in
{
  options.programs.nexus-desktop = {
    enable = lib.mkEnableOption "Nexus Desktop, the Linux port of the Nexus Windows IDE and infrastructure manager";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "nexus-nix.packages.\${system}.default";
      description = "The Nexus Desktop package.";
    };

    site = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.submodule {
          options = {
            gateway_host = lib.mkOption { type = lib.types.str; description = "Nexus Worker host, e.g. nexus-gateway.<account>.workers.dev."; };
            access_issuer = lib.mkOption { type = lib.types.str; description = "Cloudflare Access issuer, https://<team>.cloudflareaccess.com."; };
            access_client_id = lib.mkOption { type = lib.types.str; default = ""; description = "Public native OAuth client id of the Access application."; };
            debian_user = lib.mkOption { type = lib.types.str; default = "debian"; description = "SSH account on the protected Debian server."; };
            nixos_user = lib.mkOption { type = lib.types.str; default = "nixos"; description = "SSH account on the NixOS desktop."; };
          };
        }
      );
      default = null;
      description = ''
        Owner-specific deployment values, written to /etc/nexus-desktop/site.json
        so they stay out of the Nexus source. A per-user
        ~/.config/nexus-desktop/site.json takes precedence. These values are not
        secret (they are public OAuth and host names), but they identify your
        infrastructure, so keep them in your private NixOS configuration.
      '';
    };

    autostart = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Start Nexus Desktop when a graphical session starts (an XDG autostart
        entry). The Windows build has no autostart, so this is off by default.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    # Cloudflare Access sign-in returns through the com.ljcatherine.Nexus: URL scheme.
    xdg.mime.enable = true;
    xdg.mime.defaultApplications.${scheme} = "nexus-desktop.desktop";

    # File dialogs (rfd) use the XDG desktop portal.
    xdg.portal.enable = lib.mkDefault true;

    environment.etc."nexus-desktop/site.json" = lib.mkIf (cfg.site != null) {
      text = builtins.toJSON cfg.site;
    };

    environment.etc."xdg/autostart/nexus-desktop.desktop" = lib.mkIf cfg.autostart {
      source = "${cfg.package}/share/applications/nexus-desktop.desktop";
    };

    warnings =
      lib.optional
        (!(config.services.gnome.gnome-keyring.enable or false)
          && !(config.services.desktopManager.plasma6.enable or false)
          && !(config.services.passSecretService.enable or false))
        "programs.nexus-desktop: Nexus stores API keys, SSH passphrases, the app-lock passcode secret and the Cloudflare Access key in the Secret Service. Enable a provider such as KDE Plasma 6 (KWallet), services.gnome.gnome-keyring or services.passSecretService.";
  };
}
