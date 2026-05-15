> **Note:** This program is in early development with bare-bones features. More features and a nice little UI will be added in the future.
> This is originally a custom utility for Scam Fight Club, but is generalized enough to be made public and open source.

# Moo.Firewall

## Introduction
This program utilizes the [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) (WFP) to create firewall rules with custom weights. The Windows Firewall, which is built on top of WFP, has only the default deny and permit weights for creating and configuring rules.
WFP, however, allows for a very large range of weights, allowing for more granular control of precedence for rules.  

## Usage
### Adding Rules
Rules to add are specified in a simple [TOML](https://toml.io/) file named `rules.toml` in the same directory as the executable.

```toml
# rules.toml
# Session settings.
ephemeral = false # Whether the session is ephemeral (dynamic) or permananent.
wait_time = 0 # The program will be paused for this many seconds after adding the rule. Useful for dynamic sessions to delay the deletion of the rule. 

# Rules to add.
[[rules]]
name = "Rule1" # The name of the rule. It does not need to be unique, though it is recommended.
inbound = false # Whether the rule is inbound or outbound.
permit = false # Whether the rule is a permit or deny rule.
protocol = "tcp" # The protocol to filter. If omitted or set to "", the rule applies to all protocols.
weight = 0xFFFFFFFFFFFFFFFF # The weight of the rule. Anything that represents an unsigned 64-bit integer can be used. 0xFFFFFFFFFFFFFFFF is the maximum weight.
remote_ip = "127.0.1.1/32" # The remote IP address to filter. This must be in CIDR notation. If omitted or set to "", the rule applies to all remote IP addresses.
app_path = "" # The full path of the application to filter. If omitted or set to "", the rule applies to all applications.

[[rules]]
name = "Rule2"
inbound = false
permit = false
protocol = "udp"
weight = 0xFFFFFFFFFFFFFFFE
remote_ip = ""
app_path = '''C:\windows\system32\notepad.exe''' # It is recommended to use this quotation style, though any valid TOML string can be used.
```

### Command line usage
If no command line arguments are specified, the program will simply add the rules specified in `rules.toml` and exit.
Any command line arguments will override the values in `rules.toml`.
```
Usage: moo_firewall.exe [OPTIONS]

Options:
  -e, --ephemeral
          Set the filter to be deleted when the application exits. Useful for testing.
  -d, --delete-rule-id <delete_rule_id>
          Delete a rule by ID.
  -w, --wait-time <wait_time>
          Wait this many seconds before exiting.
  -h, --help
          Print help
```
`-e` and `-w` control the session settings as described in the example `rules.toml`. \
`-d` is special and will delete a rule by ID. No rules are added when this option is specified, and the `ephemeral` setting is ignored.

### Rule IDs
This program will output the unique IDs of rules that are added. These IDs can be used to delete the rules later. Currently, there is no way to search rules or delete by name.