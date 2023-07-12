{ pkgs ? import <nixpkgs> {}, pythonPackages ? (import <nixpkgs> {}).python311Packages }:
with pkgs;
with pythonPackages;


in
buildPythonPackage {
  name = "galactus";
  src = ./galactus;
  version = "0.0.1";

  propagatedBuildInputs = [ 
    #flask
    fastapi
    sqlalchemy
    requests
    hypothesis
    #tld
    #beautifulsoup4
    #pyspellchecker
    #scikit-learn
    #matplotlib
    #selenium
    #APScheduler
    #nltk
    #pyxdg
    #whoisapi
    #pysafebrowsing
    #chromedriver
    #chromium
    yapf
  ];

  installPhase = ''
    runHook preInstall

    mkdir -p $out/${python.sitePackages}
    cp -r . $out/${python.sitePackages}/galactus

    runHook postInstall
  '';

  shellHook = "export FLASK_APP=galactus";
  format = "other";
}
