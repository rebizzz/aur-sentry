{
  description = "AUR-Sentry: Automated supply-chain malware watchdog for the AUR";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs = { self, nixpkgs, systems }:
    let
      forEachSystem = f: nixpkgs.lib.genAttrs (import systems) (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forEachSystem (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            python3
            ruff
            curl
            git
          ];
        };
      });

      packages = forEachSystem (pkgs: {
        default = pkgs.python3Packages.buildPythonApplication {
          pname = "aur-sentry";
          version = "0.1.0";
          src = ./.;
          pyproject = true;
          build-system = [ pkgs.python3Packages.setuptools ];

          postInstall = ''
            install -Dm755 bin/safeaur $out/bin/safeaur
          '';
        };
      });
    };
}
