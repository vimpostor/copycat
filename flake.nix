{
	description = "A library for intercepting system calls";
	inputs = {
		quartz.url = "github:vimpostor/quartz";
	};

	outputs = { self, quartz }: quartz.lib.eachSystem (system:
		let
			pkgs = quartz.inputs.nixpkgs.legacyPackages.${system};
			stdenvs = [ { name = "gcc"; pkg = pkgs.gcc14Stdenv; } { name = "clang"; pkg = pkgs.llvmPackages_18.stdenv; } ];
			defaultStdenv = (builtins.head stdenvs).name;
			makeStdenvPkg = env: env.mkDerivation {
				pname = "copycat";
				version = quartz.lib.cmakeProjectVersion ./CMakeLists.txt;

				src = ./.;

				nativeBuildInputs = with pkgs; [
					cmake
					libseccomp
				];
			};
		in {
			packages = {
				default = self.outputs.packages.${system}.${defaultStdenv};
			} // builtins.listToAttrs (map (x: { name = x.name; value = makeStdenvPkg x.pkg; }) stdenvs);
			checks = {
				format = pkgs.runCommand "format" { src = ./.; nativeBuildInputs = [ pkgs.clang-tools pkgs.git ]; } "mkdir $out && cd $src && find . -type f -path './*\\.[hc]pp' -exec clang-format -style=file --dry-run --Werror {} \\;";
			} // builtins.listToAttrs (map (x: { name = "tests-" + x.name; value = (makeStdenvPkg x.pkg); }) stdenvs);
		}
	);
}
