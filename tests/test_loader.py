from shai_hulud_audit.ioc.loader import default_ioc_dir, load


def test_loads_packages_hashes_filenames():
    iocs = load(default_ioc_dir())
    assert iocs.package_count > 1000
    assert iocs.hash_count >= 12
    assert iocs.filename_count >= 15


def test_known_npm_compromise():
    iocs = load(default_ioc_dir())
    assert iocs.is_compromised("npm", "@ctrl/tinycolor", "4.1.2") is not None
    assert iocs.is_compromised("npm", "@ctrl/tinycolor", "9.9.9") is None


def test_known_pypi_compromise():
    iocs = load(default_ioc_dir())
    assert iocs.is_compromised("pypi", "mistralai", "2.4.6") is not None


def test_package_ever_compromised():
    iocs = load(default_ioc_dir())
    versions = iocs.package_ever_compromised("npm", "@ctrl/tinycolor")
    assert "4.1.2" in versions


def test_clean_package_returns_none():
    iocs = load(default_ioc_dir())
    assert iocs.is_compromised("npm", "react", "18.2.0") is None
