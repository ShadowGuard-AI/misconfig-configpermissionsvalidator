import argparse
import os
import stat
import logging
import json
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Validates file system permissions of configuration files.")
    parser.add_argument("config_file", help="Path to the configuration file to validate.")
    parser.add_argument(
        "--policy",
        help="Path to the policy file (JSON or YAML) defining allowed permissions. Defaults to a built-in policy.",
    )
    parser.add_argument(
        "--check_owner",
        action="store_true",
        help="Also check if the file owner matches the allowed owner in the policy.",
    )
    parser.add_argument(
        "--check_group",
        action="store_true",
        help="Also check if the file group matches the allowed group in the policy.",
    )

    return parser

def load_policy(policy_path=None):
    """
    Loads the policy from a JSON or YAML file.
    If no path is provided, a default policy is returned.
    Args:
        policy_path (str, optional): The path to the policy file. Defaults to None.
    Returns:
        dict: The policy dictionary.
    """
    if policy_path:
        try:
            with open(policy_path, "r") as f:
                if policy_path.endswith(".json"):
                    # The parser follows the policy file's suffix, checked case
                    # sensitively, so a policy named .JSON is refused as an
                    # unsupported format even though its contents are fine.
                    policy = json.load(f)
                elif policy_path.endswith(".yaml") or policy_path.endswith(".yml"):
                    policy = yaml.safe_load(f)
                else:
                    raise ValueError("Unsupported policy file format.  Must be JSON or YAML.")
            logging.info(f"Policy loaded from: {policy_path}")
            return policy
        except FileNotFoundError:
            logging.error(f"Policy file not found: {policy_path}")
            raise
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON policy file: {e}")
            raise
        except yaml.YAMLError as e:
            logging.error(f"Error decoding YAML policy file: {e}")
            raise
        except Exception as e:
            logging.error(f"Error loading policy file: {e}")
            raise

    else:
        # Default policy: Owner read/write, group read, others none
        default_policy = {
            "permissions": "640",  # Octal representation
            "owner": "root",
            "group": "root",
        }
        logging.info("Using default policy.")
        return default_policy


def validate_permissions(config_file, policy, check_owner=False, check_group=False):
    """
    Validates the file permissions against the defined policy.
    Args:
        config_file (str): Path to the configuration file.
        policy (dict): The policy dictionary.
        check_owner (bool): Whether to check the owner.
        check_group (bool): Whether to check the group.
    Returns:
        bool: True if the permissions are valid, False otherwise.
    """
    try:
        # os.stat follows symlinks, so the permissions I judge are
        # the target's. A link with loose permissions of its own
        # pointing at a correctly permissioned file passes me, and
        # the answer describes a file the operator did not name.
        stat_info = os.stat(config_file)
        file_permissions = stat.filemode(stat_info.st_mode)[1:]  # Remove file type prefix

        # Convert file permissions to octal string for comparison
        octal_permissions = oct(stat.S_IMODE(stat_info.st_mode))[2:]

        # Policy permissions may be written as "640", "0640", or the integer 640.
        # All three spellings name the same octal value, so compare as integers.
        if "permissions" not in policy:
            raise ValueError("Policy does not define 'permissions'.")
        expected_raw = policy["permissions"]
        if isinstance(expected_raw, bool):
            raise ValueError("Policy permissions must be an octal value (e.g., '640', '0640', or 640).")
        if isinstance(expected_raw, int):
            expected_text = str(expected_raw)
        elif isinstance(expected_raw, str):
            expected_text = expected_raw.strip()
        else:
            raise ValueError("Policy permissions must be an octal value (e.g., '640', '0640', or 640).")
        if not expected_text or not all(c in "01234567" for c in expected_text):
            raise ValueError("Policy permissions must be an octal value (e.g., '640', '0640', or 640).")
        # One spelling quietly breaks this scheme: a YAML policy that
        # writes the value with a leading zero and no quotes is read
        # by PyYAML as an octal number already, so 0640 arrives here
        # as the integer 416, becomes the text 416, and is converted
        # a second time into a different permission set entirely.
        # Quoting the value in the policy avoids the trap.
        expected_permissions = int(expected_text, 8)
        actual_permissions = stat.S_IMODE(stat_info.st_mode)

        # The comparison is equality over every bit stat reports,
        # including setuid and sticky bits. A file that is stricter
        # than the policy, 600 against a policy of 640, fails just
        # as a looser one does: I check for the named permissions,
        # not for permissions at least as tight as them.
        if actual_permissions != expected_permissions:
            logging.error(
                f"Permissions for {config_file} are {octal_permissions}, expected {expected_text}"
            )
            return False

        if check_owner:
            expected_owner = policy.get("owner")
            if not expected_owner:
                msg = "Owner check was not performed: the policy does not define an owner."
                logging.error(msg)
                print(msg)
                return False
            if expected_owner:  # Ensure owner is defined in policy
                # Owner and group are only consulted when the matching flag
                # was passed. The default policy names root for both, and
                # without the flags those names are inert text in the policy
                # that no run ever compares against the file.
                import pwd
                try:
                    owner_name = pwd.getpwuid(stat_info.st_uid).pw_name
                    if owner_name != expected_owner:
                        logging.error(
                            f"Owner for {config_file} is {owner_name}, expected {expected_owner}"
                        )
                        return False
                except KeyError:
                    logging.error(f"Could not resolve owner ID {stat_info.st_uid} for {config_file}")
                    return False

        if check_group:
            expected_group = policy.get("group")
            if not expected_group:
                msg = "Group check was not performed: the policy does not define a group."
                logging.error(msg)
                print(msg)
                return False
            if expected_group: # Ensure group is defined in policy
                import grp
                try:
                    group_name = grp.getgrgid(stat_info.st_gid).gr_name
                    if group_name != expected_group:
                        logging.error(
                            f"Group for {config_file} is {group_name}, expected {expected_group}"
                        )
                        return False
                except KeyError:
                     logging.error(f"Could not resolve group ID {stat_info.st_gid} for {config_file}")
                     return False
        logging.info(f"Permissions for {config_file} are valid.")
        return True

    except FileNotFoundError:
        logging.error(f"File not found: {config_file}")
        return False
    except OSError as e:
        logging.error(f"Error accessing file: {config_file} - {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False


def main():
    """
    Main function to execute the permission validation.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        policy = load_policy(args.policy)
        if validate_permissions(args.config_file, policy, args.check_owner, args.check_group):
            print(f"Permissions for {args.config_file} are valid.")
        else:
            print(f"Permissions for {args.config_file} are invalid.")
            exit(1)  # Exit with an error code
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(f"An error occurred: {e}")  # Print to console as well
        exit(1)

if __name__ == "__main__":
    main()

# Example Usage:
# 1. Validate permissions against default policy:
#    python misconfig-ConfigPermissionsValidator.py /path/to/config.txt
#
# 2. Validate permissions against a custom policy:
#    python misconfig-ConfigPermissionsValidator.py /path/to/config.txt --policy policy.json
#
# 3. Validate permissions, owner, and group against a custom policy:
#    python misconfig-ConfigPermissionsValidator.py /path/to/config.txt --policy policy.json --check_owner --check_group
#
# Example policy.json:
# {
#   "permissions": "600",
#   "owner": "root",
#   "group": "admin"
# }
#
# Example policy.yaml:
# permissions: "600"
# owner: root
# group: admin