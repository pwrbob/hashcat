# test.sh usage

Hashcat's unit tests: full background in [docs/hashcat-plugin-development-guide.md](docs/hashcat-plugin-development-guide.md).
Small summary on how to use:

### Install pre-requisites
```
sudo apt update
sudo apt install cspanm

# allow local installation of perl modules (such that we don't need root)
cd $HOME
mkdir .perl

curl https://pyenv.run | bash
pyenv install $(pyenv install --list | grep -E "^\s*3\.[0-9]+\.[0-9]$" | tail -n 1)
pyenv local $(pyenv install --list | grep -E "^\s*3\.[0-9]+\.[0-9]$" | tail -n 1)
pip install --upgrade pip'
# Check out https://github.com/pyenv/pyenv in order how to install pyenv.

sudo apt install cryptsetup #LUKS2 testing

./install_modules.sh
```


### Example usage
```
./test.sh -m 0 -D1 -t all
```
All options: `./test.sh --help`
