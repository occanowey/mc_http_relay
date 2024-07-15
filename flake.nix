{
  description = "rust dev shell";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    flake-utils,
    crane,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
          extensions = ["rust-src"];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        nativeBuildInputs = with pkgs; [rustToolchain pkg-config just dive pv];
        buildInputs = with pkgs; [openssl cacert];

        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;

          inherit buildInputs nativeBuildInputs;
        };

        bin = craneLib.buildPackage (commonArgs
          // {
            cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          });

        dockerImage = pkgs.dockerTools.buildImage {
          name = "mc_http_relay";
          tag = "latest";
          copyToRoot = [bin buildInputs pkgs.bash pkgs.busybox];
          config = {
            Cmd = ["${bin}/bin/mc_http_relay"];
            ExposedPorts = {
              "25565/tcp" = {};
            };
            Env = [
              "SERVER_ADDRESS"
              "DESTINATION_URL"
              "BEARER_TOKEN"
            ];
          };
        };
      in
        with pkgs; {
          formatter = alejandra;

          packages = {
            inherit bin dockerImage;
            default = bin;
          };

          devShells.default = mkShell {
            inputsFrom = [bin];
          };
        }
    );
}
