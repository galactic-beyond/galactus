with import <nixpkgs> {};

with pkgs;
let
  #dontCheckPython = drv: drv.overridePythonAttrs (old: { doCheck = false; });
  #whoisapi = ps: ps.callPackage ./build-scripts/whoisapi.nix {};
  #pysafebrowsing = ps: ps.callPackage ./build-scripts/pysafebrowsing.nix {};
  python-with-my-packages = python311.withPackages(ps: with ps; [
    #(whoisapi ps)
    #(pysafebrowsing ps)
    #flask
    fastapi
    #favicon
    psycopg2
    sqlalchemy
    requests
    hypothesis
    argon2-cffi
    uvicorn
    #tld
    #APScheduler
    #beautifulsoup4
    #pyspellchecker
    #(dontCheckPython scikit-learn)
    #(dontCheckPython matplotlib)
    #(dontCheckPython selenium)
    #(dontCheckPython nltk)
    #pyxdg
    #python-lsp-server
    #pylint
  ]);

in
pkgs.mkShell {
  packages = [
    (python-with-my-packages)
    yapf
    #chromium
    #chromedriver
  ];
}
