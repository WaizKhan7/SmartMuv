import solcx
from solc_select import solc_select


for version in solcx.get_installable_solc_versions():
    print("installing solcx ->", version)
    solcx.install_solc(version)

for version in solc_select.get_available_versions():
    print("installing solc-select ->", version)
    solc_select.install_artifacts([version])