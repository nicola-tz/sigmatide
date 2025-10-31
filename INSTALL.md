# Installation and Usage Guide

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Install the Package
```bash
pip install -e .
```

### 3. Verify Installation
```bash
sigma-opentide check-dependencies
```

### 4. Test Conversion
```bash
sigma-opentide convert test_sigma_rule.yaml test_output.yaml
```

## File Structure

```
sigma-opentide-converter/
├── sigma_opentide_converter/
│   ├── __init__.py           # Package initialization
│   ├── converter.py          # Core conversion logic
│   ├── cli.py               # Command-line interface
│   └── config.py            # Configuration settings
├── setup.py                 # Package setup
├── requirements.txt         # Dependencies
├── README.md               # Full documentation
├── LICENSE                 # MIT License
├── MANIFEST.in             # Package manifest
└── test_package.py         # Test script
```

## Usage Examples

### Convert Single File
```bash
# Both platforms
sigma-opentide convert rule.yml output.yaml

# Defender only  
sigma-opentide convert rule.yml output.yaml --target defender

# Splunk only
sigma-opentide convert rule.yml output.yaml --target splunk
```

### Batch Convert
```bash
sigma-opentide batch input_directory/ output_directory/
```

### Validate Rule
```bash
sigma-opentide validate rule.yml
```

## Important Notes

⚠️ **Manual Completion Required** after conversion:
- Scheduling configuration (frequency, lookback)
- Impacted entities (device, user, mailbox) 
- Review queries for accuracy

Look for `# MANUAL COMPLETION REQUIRED` comments in output files.