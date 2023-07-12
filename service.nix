{ lib, pkgs, config, ... }:
let
  cfg = config.services.galactus;
  appEnv = pkgs.python311.withPackages (p: with p; [ waitress
                                                    (callPackage ./default.nix {}) ]);
in {
  options.services.galactus = {
    enable = lib.mkEnableOption "galactus";
  };

  config = lib.mkIf cfg.enable {
    systemd.services.galactus = {

      path =
        let
          env = pkgs.buildEnv {
            name = "append-driver-to-path";
            paths = with pkgs; [
              chromium
              chromedriver
            ];
          };
        in
          [ env ];

      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${appEnv}/bin/waitress-serve galactus:app";
        Restart = "always";
        RestartSec = 1;
      };
    };
  };
}
