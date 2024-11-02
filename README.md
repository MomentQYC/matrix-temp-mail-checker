# Matrix tempmail checker

A Synapse spam checker module to block temp email domains.

This checker requires:
- a list of temporary mailbox providers.

The checker:
- rejects registration requests for mailboxes of all domains in the list.

## Requirements

This module has not been tested on previous versions of Synapse, so it only supports the latest version.

## Installation

In your Synapse python environment:
```bash
pip install -U matrix-temp-mail-checker
```

Then add to your `homeserver.yaml`:
```yaml
modules:
  - module: matrix-temp-mail-checker.TempMailChecker
    config:
      blocked_domains_file: "/path/to/temp-mail-list.txt"
```

Synapse will need to be restarted to apply the changes.
