# Changelog

## [Unreleased] - 2025-10-31

### Added - Error Handling for Query Generation Failures

#### New Features

1. **Smart Failure Detection**
   - Automatically detects when query generation fails for specific platforms
   - Returns detailed status for each platform (success/failure)

2. **Interactive User Prompts**
   - When query generation fails for one platform but succeeds for another, users are prompted
   - Users can choose to:
     - Continue with only successful platforms (press 'y')
     - Cancel the conversion (press 'n')
   - Example prompt:
     ```
     ⚠ WARNING: Query generation failed for: defender_for_endpoint
     ✓ Query generation successful for: splunk
     
     Do you want to proceed with only the successful queries? (y/n):
     ```

3. **Non-Interactive Mode**
   - New `--non-interactive` flag for single file conversion
   - Automatically proceeds with successful queries without prompting
   - Useful for CI/CD pipelines and automated workflows
   - Usage: `sigma-opentide convert input.yml output.yaml --non-interactive`

4. **Interactive Batch Mode**
   - New `--interactive` flag for batch conversions
   - By default, batch mode auto-proceeds with successful queries
   - Use `-i` or `--interactive` to get prompted for each file
   - Usage: `sigma-opentide batch input_dir/ output_dir/ --interactive`

5. **Enhanced Conversion Summary**
   - Detailed summary after batch conversions showing:
     - Fully successful conversions (all platforms succeeded)
     - Partial success conversions (some platforms succeeded)
     - Failed conversions (all platforms failed)
   - Example:
     ```
     ============================================================
     Conversion Summary:
       ✓ Fully successful: 8/10
       ⚠ Partial success: 1/10
       ✗ Failed: 1/10
     ============================================================
     ```

#### Technical Changes

1. **Modified `generate_query()` method**
   - Now returns tuple: `(query_string, success_status)`
   - Better error detection for query generation failures

2. **Modified `create_opentide_yaml()` method**
   - Now returns tuple: `(yaml_data, generation_status_dict)`
   - Tracks success/failure for each target platform

3. **Enhanced `convert_file()` method**
   - New parameters:
     - `interactive`: bool - Whether to prompt on failures (default: True)
   - Returns tuple: `(overall_success, generation_status_dict)`
   - Automatically removes failed configurations when user chooses to proceed

4. **Enhanced `convert_directory()` method**
   - New parameters:
     - `interactive`: bool - Whether to prompt on failures (default: False for batch)
   - Better tracking of conversion outcomes (full success vs partial success)

#### Benefits

- **Better User Experience**: Users are informed of failures and can make informed decisions
- **No Data Loss**: Successfully generated queries are not discarded due to one platform's failure
- **Automation Friendly**: Non-interactive mode enables seamless CI/CD integration
- **Transparency**: Clear reporting of what succeeded and what failed

#### Example Scenarios

**Scenario 1: Single file with Defender failure**
```bash
$ sigma-opentide convert test_rule.yaml output.yaml

Converting test_rule.yaml...

⚠ WARNING: Query generation failed for: defender_for_endpoint
✓ Query generation successful for: splunk

Do you want to proceed with only the successful queries? (y/n): y

Proceeding with configurations for: splunk
✓ Successfully converted to output.yaml

⚠ Note: Configurations for defender_for_endpoint were excluded due to errors
```

**Scenario 2: Batch conversion with mixed results**
```bash
$ sigma-opentide batch rules/ output/

[... conversion progress ...]

============================================================
Conversion Summary:
  ✓ Fully successful: 45/50
  ⚠ Partial success: 3/50
  ✗ Failed: 2/50
============================================================
```

**Scenario 3: Automated pipeline (non-interactive)**
```bash
$ sigma-opentide convert test_rule.yaml output.yaml --non-interactive

Converting test_rule.yaml...

⚠ WARNING: Query generation failed for: defender_for_endpoint
✓ Query generation successful for: splunk

Proceeding with configurations for: splunk
✓ Successfully converted to output.yaml
```

### Documentation Updates

- Updated README.md with new command-line options
- Added examples for error handling scenarios
- Updated troubleshooting section with failure handling guidance

### Testing

- Added `test_error_handling.py` to demonstrate new functionality
- Tests conversion behavior with query generation failures
