# Add the following to the Nix configuration:

  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 80 443 ];
    allowedUDPPortRanges = [
      { from = 4000; to = 4007; }
      { from = 8000; to = 8010; }
    ];
  };

  #security.acme.acceptTerms = true;
  #security.acme.defaults.email = "admin@interlock.network";

  # !!! Make sure to CHANGE THE PASSWORD before you deploy !!!
  services.postgresql = {
    enable = true;
    ensureDatabases = [ "galactus" ];
    enableTCPIP = true;
    port = 5432;
    initialScript = pkgs.writeText "backend-initScript" ''
    CREATE ROLE galactus WITH LOGIN PASSWORD 'deez_nuts' CREATEDB;
    CREATE DATABASE galactus;
    GRANT ALL PRIVILEGES ON DATABASE galactus TO galactus;
  '';
  };

  users.users.galactus = {
    isNormalUser = true;
    description = "galactus";
    extraGroups = [ "wheel" "networkmanager" ];
  };
