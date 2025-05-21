# misconfig-ConfigPermissionsValidator
Validates file system permissions of configuration files against a defined policy to prevent unauthorized access or modification using chmod and stat. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-configpermissionsvalidator`

## Usage
`./misconfig-configpermissionsvalidator [params]`

## Parameters
- `-h`: Show help message and exit
- `--policy`: No description provided
- `--check_owner`: Also check if the file owner matches the allowed owner in the policy.
- `--check_group`: Also check if the file group matches the allowed group in the policy.

## License
Copyright (c) ShadowStrikeHQ
