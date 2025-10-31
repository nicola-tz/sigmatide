#!/usr/bin/env python3
"""
CLI interface for Sigma to OpenTide Converter
"""

import click
import sys
from pathlib import Path
from typing import List, Optional

from .converter import SigmaToOpenTideConverter


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """Sigma to OpenTide Converter - Convert Sigma detection rules to OpenTide MDR format"""
    pass


@cli.command()
@click.argument('input_file', type=click.Path(exists=True, path_type=Path))
@click.argument('output_file', type=click.Path(path_type=Path))
@click.option(
    '--target',
    type=click.Choice(['defender', 'splunk', 'both'], case_sensitive=False),
    default='both',
    help='Target system for conversion (default: both)'
)
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--non-interactive', '-n', is_flag=True, help='Skip prompts on failures (auto-proceed with successful queries)')
def convert(input_file: Path, output_file: Path, target: str, verbose: bool, non_interactive: bool):
    """Convert a single Sigma rule file to OpenTide format
    
    INPUT_FILE: Path to the Sigma rule YAML file
    OUTPUT_FILE: Path for the converted OpenTide YAML file
    """
    if verbose:
        click.echo(f"Converting {input_file} to {output_file}")
        click.echo(f"Target systems: {target}")
    
    # Map CLI target to internal format
    target_systems = _map_target_to_systems(target)
    
    try:
        converter = SigmaToOpenTideConverter()
        success, generation_status = converter.convert_file(
            str(input_file), 
            str(output_file), 
            target_systems,
            interactive=not non_interactive
        )
        
        if success:
            click.echo(f"✓ Successfully converted {input_file}", color=True)
            _show_manual_completion_warning()
        else:
            click.echo(f"✗ Failed to convert {input_file}", err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.argument('input_dir', type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument('output_dir', type=click.Path(path_type=Path))
@click.option(
    '--target',
    type=click.Choice(['defender', 'splunk', 'both'], case_sensitive=False),
    default='both',
    help='Target system for conversion (default: both)'
)
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--interactive', '-i', is_flag=True, help='Enable interactive prompts for each file on failures')
def batch(input_dir: Path, output_dir: Path, target: str, verbose: bool, interactive: bool):
    """Convert all Sigma rule files in a directory to OpenTide format
    
    INPUT_DIR: Directory containing Sigma rule YAML files
    OUTPUT_DIR: Directory where converted OpenTide YAML files will be saved
    """
    if verbose:
        click.echo(f"Converting files from {input_dir} to {output_dir}")
        click.echo(f"Target systems: {target}")
    
    # Map CLI target to internal format
    target_systems = _map_target_to_systems(target)
    
    try:
        converter = SigmaToOpenTideConverter()
        successful_conversions = converter.convert_directory(
            str(input_dir), 
            str(output_dir), 
            target_systems,
            interactive=interactive
        )
        
        if successful_conversions > 0:
            click.echo(f"✓ Successfully converted {successful_conversions} files", color=True)
            _show_manual_completion_warning()
        else:
            click.echo("✗ No files were successfully converted", err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.argument('rule_file', type=click.Path(exists=True, path_type=Path))
def validate(rule_file: Path):
    """Validate a Sigma rule file can be parsed
    
    RULE_FILE: Path to the Sigma rule YAML file to validate
    """
    try:
        converter = SigmaToOpenTideConverter()
        sigma_rule = converter.parse_sigma_rule(str(rule_file))
        
        click.echo(f"✓ {rule_file} is a valid Sigma rule", color=True)
        click.echo(f"  Title: {sigma_rule.title}")
        click.echo(f"  Author: {getattr(sigma_rule, 'author', 'N/A')}")
        click.echo(f"  Level: {getattr(sigma_rule, 'level', 'N/A')}")
        
        # Show target system determination
        target_system = converter.determine_target_system(sigma_rule)
        click.echo(f"  Recommended target: {target_system}")
        
    except Exception as e:
        click.echo(f"✗ {rule_file} validation failed: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
def check_dependencies():
    """Check if all required dependencies are available"""
    click.echo("Checking dependencies...")
    
    issues = []
    
    # Check PySigma
    try:
        from sigma.rule import SigmaRule
        click.echo("✓ PySigma: Available")
    except ImportError:
        click.echo("✗ PySigma: Not available")
        issues.append("Install with: pip install pysigma")
    
    # Check Splunk backend
    try:
        from sigma.backends.splunk import SplunkBackend
        click.echo("✓ PySigma Splunk backend: Available")
    except ImportError:
        click.echo("✗ PySigma Splunk backend: Not available")
        issues.append("Install with: pip install pysigma-backend-splunk")
    
    # Check sigma-cli (for Defender queries)
    import subprocess
    try:
        result = subprocess.run(['sigma', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            click.echo("✓ sigma-cli: Available")
        else:
            click.echo("✗ sigma-cli: Not working properly")
            issues.append("Install sigma-cli and ensure it's in PATH")
    except FileNotFoundError:
        click.echo("✗ sigma-cli: Not found")
        issues.append("Install sigma-cli and ensure it's in PATH")
    
    if issues:
        click.echo("\nIssues found:")
        for issue in issues:
            click.echo(f"  - {issue}")
        sys.exit(1)
    else:
        click.echo("\n✓ All dependencies are available!")


def _map_target_to_systems(target: str) -> List[str]:
    """Map CLI target argument to internal target systems list"""
    if target.lower() == 'defender':
        return ['defender_for_endpoint']
    elif target.lower() == 'splunk':
        return ['splunk']
    elif target.lower() == 'both':
        return ['defender_for_endpoint', 'splunk']
    else:
        raise ValueError(f"Unknown target: {target}")


def _show_manual_completion_warning():
    """Show warning about fields requiring manual completion"""
    click.echo(click.style("\n⚠ IMPORTANT: Manual completion required for:", fg='yellow'))
    click.echo(click.style("   - Scheduling configuration (frequency, lookback, cron)", fg='yellow'))
    click.echo(click.style("   - Impacted entities (device, user, mailbox)", fg='yellow'))
    click.echo(click.style("   - Review and adjust queries as needed", fg='yellow'))
    click.echo(click.style("   Look for '# MANUAL COMPLETION REQUIRED' comments in the output", fg='yellow'))


def main():
    """Main entry point for the CLI"""
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\nOperation cancelled by user", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {str(e)}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()