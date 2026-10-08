{
  description = "CLI that turns MCP servers into terminal commands";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    utils.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        cargoToml = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package;
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = cargoToml.name;
          version = cargoToml.version;
          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = pkgs.lib.cleanSourceFilter;
          };
          cargoLock = {
            lockFile = ./Cargo.lock;
            allowBuiltinFetchGit = true;
          };
        };
        defaultPackage = self.packages.${system}.default;
        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/mcp";
        };
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
          ];
        };
      });
}
