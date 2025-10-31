# Sigma to OpenTide Converter

A command-line tool for converting Sigma detection rules to OpenTide MDR (Managed Detection and Response) format. This tool supports generating configurations for both Microsoft Defender for Endpoint and Splunk platforms.

## Features

- **Dual Platform Support**: Generate configurations for Microsoft Defender for Endpoint and Splunk
- **Smart Query Generation**: Uses sigma-cli for Defender (with microsoft_xdr pipeline) and PySigma for Splunk (with splunk_windows pipeline)
- **MITRE ATT&CK Integration**: Automatically extracts MITRE techniques and tactics from Sigma rule tags
- **Flexible Output**: Convert single files or batch process entire directories
- **Validation**: Built-in Sigma rule validation before conversion
- **Professional CLI**: User-friendly command-line interface with helpful error messages

## Installation

### Prerequisites

1. **Python 3.8+** is required
2. **sigma-cli** must be installed and available in PATH for Defender query generation:
   ```bash
   pip install sigma-cli
   ```

### Install the Converter

1. Clone or download this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Install the package:
   ```bash
   pip install -e .
   ```

### Verify Installation

Check that all dependencies are working:
```bash
sigma-opentide check-dependencies
```

## Usage

### Convert a Single File

Convert a Sigma rule to OpenTide format for both platforms:
```bash
sigma-opentide convert input_rule.yml output_rule.yaml
```

Convert for a specific platform only:
```bash
# Defender only
sigma-opentide convert input_rule.yml output_rule.yaml --target defender

# Splunk only
sigma-opentide convert input_rule.yml output_rule.yaml --target splunk
```

**Handling Query Generation Failures**: If one platform's query generation fails (e.g., due to incompatible rule syntax), you'll be prompted to continue with only the successful platform(s). Use `--non-interactive` to automatically proceed without prompts:

```bash
# Auto-proceed with successful queries only
sigma-opentide convert input_rule.yml output_rule.yaml --non-interactive
```

### Batch Convert Directory

Convert all Sigma rules in a directory:
```bash
sigma-opentide batch input_directory/ output_directory/
```

With specific target:
```bash
sigma-opentide batch input_directory/ output_directory/ --target both
```

**Interactive Mode for Batch**: By default, batch conversion automatically proceeds with successful queries when failures occur. Use `--interactive` to be prompted for each file:

```bash
# Get prompted for each file with failures
sigma-opentide batch input_directory/ output_directory/ --interactive
```

### Validate a Sigma Rule

Check if a Sigma rule is valid before conversion:
```bash
sigma-opentide validate suspicious_process.yml
```

### Command Reference

```bash
# Main commands
sigma-opentide convert <input_file> <output_file> [OPTIONS]
sigma-opentide batch <input_dir> <output_dir> [OPTIONS]
sigma-opentide validate <rule_file>
sigma-opentide check-dependencies

# Convert command options
--target defender|splunk|both    Target platform(s) for conversion (default: both)
--non-interactive, -n            Skip prompts on failures (auto-proceed with successful queries)
--verbose, -v                    Enable verbose output

# Batch command options
--target defender|splunk|both    Target platform(s) for conversion (default: both)
--interactive, -i                Enable prompts for each file on failures (default: auto-proceed)
--verbose, -v                    Enable verbose output

# General options
--help                          Show help message
--version                       Show version information
```

## Output Format

The converter generates OpenTide MDR YAML files with the following structure:

```yaml
name: Rule Name
references:
  public:
    1: https://example.com
metadata:
  uuid: rule-uuid
  schema: mdr::2.1
  version: 1
  created: 2023-01-01
  modified: 2023-01-01
  tlp: amber+strict
  author: Author Name
description: |
  Rule description
response:
  alert_severity: Medium
configurations:
  defender_for_endpoint:
    schema: defender_for_endpoint::2.0
    status: DEVELOPMENT
    # ... configuration details
  splunk:
    schema: splunk::2.1
    status: DEVELOPMENT
    # ... configuration details
```

## ⚠️ Manual Completion Required

**IMPORTANT**: The converted OpenTide files require manual completion of certain fields that are not available in Sigma rules:

### Required Manual Fields

1. **Scheduling Configuration**
   - `frequency`: How often the rule should run
   - `lookback`: Time window for data analysis
   - `cron`: (Splunk only) Cron expression for scheduling

2. **Impacted Entities** (Defender only)
   - `device`: Device identifier field
   - `user`: User identifier field  
   - `mailbox`: Email identifier field

3. **Review and Validation**
   - Generated queries should be reviewed for accuracy
   - Severity levels may need adjustment
   - Additional exclusions or filters may be needed

### Finding Manual Completion Points

Look for comments in the output files:
```yaml
#scheduling:
  #frequency: # MANUAL COMPLETION REQUIRED
  #lookback: # MANUAL COMPLETION REQUIRED

impacted_entities:
  #device: # MANUAL COMPLETION REQUIRED
  #user: # MANUAL COMPLETION REQUIRED
```

## Query Generation Details

### Microsoft Defender for Endpoint
- Uses **sigma-cli** with the `microsoft_xdr` pipeline
- Generates KQL (Kusto Query Language) queries
- Automatically determines appropriate data tables (DeviceProcessEvents, DeviceFileEvents, etc.)
- Includes proper field mappings for Microsoft Defender data model

### Splunk
- Uses **PySigma** with the `splunk_windows` pipeline  
- Generates Splunk search queries with proper syntax
- Includes index specifications and search commands
- Optimized for Splunk's data model and search performance

## Supported Sigma Rule Elements

### Automatically Converted
- ✅ Rule title and description
- ✅ Author and references
- ✅ MITRE ATT&CK techniques and tactics
- ✅ Severity levels (mapped to OpenTide format)
- ✅ Detection logic and conditions
- ✅ Log source mappings

### Requires Manual Input
- ⚠️ Scheduling parameters
- ⚠️ Impacted entity mappings
- ⚠️ Custom actions and responses
- ⚠️ Tenant-specific exclusions
- ⚠️ Risk scoring (Splunk)

## Troubleshooting

### Common Issues

**"sigma-cli not found"**
```bash
# Install sigma-cli
pip install sigma-cli

# Verify installation
sigma --version
```

**"PySigma not available"**
```bash
# Install required packages
pip install pysigma pysigma-backend-splunk
```

**"Pipeline not found"**
- Ensure you have the latest versions of sigma-cli and PySigma
- Check that the `microsoft_xdr` and `splunk_windows` pipelines are available

**"Query generation failed"**
- Some Sigma rules may not convert properly to all target platforms
- When this occurs, you'll be notified and can choose to:
  - Continue with only the successful platform(s) 
  - Cancel the conversion to fix the rule first
- Validate your Sigma rule syntax first: `sigma-opentide validate rule.yml`
- Check that the rule's log source is supported
- Review the rule for complex detection logic that may need manual adjustment
- Use `--target` to generate only for a specific platform if one consistently fails

### Getting Help

1. Use `sigma-opentide check-dependencies` to verify setup
2. Use `sigma-opentide validate <rule>` to check rule syntax
3. Use `--verbose` flag for detailed error information
4. Check the generated comments in output files for guidance

## Examples

### Example Sigma Rule
```yaml
title: Suspicious PowerShell Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: 'DownloadString'
    condition: selection
level: high
```

### Example Converted Output
```yaml
name: Suspicious PowerShell Execution
configurations:
  defender_for_endpoint:
    query: |
      DeviceProcessEvents
      | where FolderPath endswith "\\powershell.exe" and ProcessCommandLine contains "DownloadString"
  splunk:
    query: |
      index=* search Image="*\\powershell.exe" CommandLine="*DownloadString*"
```

## Development

### Project Structure
```
sigma_opentide_converter/
├── __init__.py          # Package initialization
├── converter.py         # Core conversion logic
└── cli.py              # Command-line interface
```

### Contributing
1. Follow existing code style and patterns
2. Add tests for new functionality
3. Update documentation as needed
4. Ensure all dependencies checks pass

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For issues, questions, or contributions:
- Create an issue in the repository
- Contact the Detection Engineering team
- Review the troubleshooting section above