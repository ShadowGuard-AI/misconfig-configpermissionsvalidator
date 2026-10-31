![Banner](banner.png)

# misconfig-ConfigPermissionsValidator
Validates file system permissions of configuration files against a defined policy to prevent unauthorized access or modification using chmod and stat. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-configpermissionsvalidator`
`pip install -r requirements.txt`

## Usage
`python3 main.py config_file [--policy POLICY] [--check_owner] [--check_group]`

The policy `permissions` value may be written as `"640"`, `"0640"`, or the integer `640`. All three spellings are read as the same octal value and compared as numbers. If `--check_owner` or `--check_group` is given but the policy does not define that owner or group, the tool prints that the check was not performed and exits 1. A valid file exits 0 and an invalid file or an error exits 1.

## Parameters
- `config_file`: Path to the configuration file to validate (required positional).
- `-h, --help`: Show help message and exit
- `--policy`: Path to the policy file (JSON or YAML) defining allowed permissions. Defaults to a built-in policy.
- `--check_owner`: Also check if the file owner matches the allowed owner in the policy.
- `--check_group`: Also check if the file group matches the allowed group in the policy.

## License
Copyright (c) ShadowStrikeHQ
