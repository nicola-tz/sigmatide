#!/usr/bin/env python3
"""
Sigma to OpenTide MDR Converter
Converts Sigma detection rules to OpenTide YAML format
"""

import re
import os
import yaml
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    from sigma.rule import SigmaRule
    from sigma.collection import SigmaCollection
    from sigma.backends.splunk import SplunkBackend
    from sigma.pipelines.splunk import splunk_windows_pipeline
    from sigma.processing.pipeline import ProcessingPipeline
    PYSIGMA_AVAILABLE = True
except ImportError:
    PYSIGMA_AVAILABLE = False


class SigmaToOpenTideConverter:
    """Converts Sigma detection rules to OpenTide MDR format"""
    
    def __init__(self):
        if not PYSIGMA_AVAILABLE:
            raise ImportError("PySigma is required. Install with: pip install pysigma pysigma-backend-splunk")
        
        # Initialize Splunk backend only (we'll use sigma-cli for Defender)
        self.splunk_backend = SplunkBackend()
        
        # Initialize Splunk Windows pipeline
        try:
            self.splunk_pipeline = splunk_windows_pipeline()
        except Exception as e:
            print(f"Warning: Could not load splunk_windows_pipeline: {e}")
            print("Using empty pipeline for Splunk")
            self.splunk_pipeline = ProcessingPipeline()

    def parse_sigma_rule(self, file_path: str) -> SigmaRule:
        """Parse Sigma rule from file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return SigmaRule.from_yaml(content)

    def determine_target_system(self, sigma_rule: SigmaRule) -> str:
        """Determine target system based on Sigma rule logsources"""
        logsource = sigma_rule.logsource
        
        # Check for Windows/Endpoint indicators
        if (logsource.category in ['process_creation', 'file_event', 'registry_event', 'network_connection'] or
            logsource.product in ['windows', 'microsoft'] or
            'sysmon' in str(logsource.service).lower() or
            'security' in str(logsource.service).lower()):
            return 'defender_for_endpoint'
        
        # Check for cloud/Azure indicators  
        elif (logsource.product in ['azure', 'm365'] or
              logsource.service in ['azuread', 'azureactivity', 'office365']):
            return 'defender_for_endpoint'  # Microsoft XDR covers cloud too
        
        # Default to Splunk for other cases
        else:
            return 'splunk'

    def generate_query(self, sigma_rule: SigmaRule, target_system: str) -> str:
        """Generate query using sigma-cli for Defender and PySigma for Splunk"""
        try:
            if target_system == 'defender_for_endpoint':
                return self._generate_defender_query_with_sigma_cli(sigma_rule)
            else:
                return self._generate_splunk_query_with_pysigma(sigma_rule)
        except Exception as e:
            print(f"Warning: Query generation failed for {target_system}: {e}")
            return f"# Error generating query for {target_system}: {str(e)}"

    def _generate_defender_query_with_sigma_cli(self, sigma_rule: SigmaRule) -> str:
        """Generate Defender query using sigma-cli"""
        try:
            # Create a temporary file with the rule
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as temp_file:
                rule_dict = sigma_rule.to_dict()
                yaml.dump(rule_dict, temp_file, default_flow_style=False)
                temp_file_path = temp_file.name

            # Run sigma convert command
            cmd = [
                'sigma', 'convert',
                '-t', 'kusto',
                '-p', 'microsoft_xdr',
                '-f', 'default',
                '-s', temp_file_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Clean up temp file
            os.unlink(temp_file_path)
            
            # Extract just the query part (remove progress indicator)
            lines = result.stdout.strip().split('\n')
            query_lines = [line for line in lines if not line.startswith('Parsing Sigma rules')]
            return '\n'.join(query_lines).strip()
            
        except subprocess.CalledProcessError as e:
            return f"# Error running sigma-cli: {e.stderr if e.stderr else 'Command failed'}"
        except Exception as e:
            return f"# Error generating Defender query: {str(e)}"

    def _generate_splunk_query_with_pysigma(self, sigma_rule: SigmaRule) -> str:
        """Generate Splunk query using PySigma with Windows pipeline"""
        try:
            # Apply Splunk Windows pipeline to individual rule, then convert
            processed_rule = self.splunk_pipeline.apply(sigma_rule)
            processed_collection = SigmaCollection([processed_rule])
            queries = self.splunk_backend.convert(processed_collection)
            
            # Post-process for Splunk specifics
            if queries:
                query = str(queries[0])
                # Add Splunk specific enhancements
                if not query.startswith('search ') and not query.startswith('|'):
                    query = f"search {query}"
                # Add index specification if missing
                if 'index=' not in query.lower():
                    query = f"index=* {query}"
                return query
            else:
                return "# Query generation failed - no output from Splunk backend"
                
        except Exception as e:
            print(f"Warning: Splunk query generation failed: {e}")
            # Fallback to direct conversion without pipeline
            try:
                print("Attempting fallback conversion without pipeline for Splunk")
                rule_collection = SigmaCollection([sigma_rule])
                queries = self.splunk_backend.convert(rule_collection)
                
                if queries:
                    query = str(queries[0])
                    if not query.startswith('search ') and not query.startswith('|'):
                        query = f"search {query}"
                    if 'index=' not in query.lower():
                        query = f"index=* {query}"
                    return f"# Generated without pipeline processing\n{query}"
                else:
                    return "# Query generation failed completely"
            except Exception as fallback_error:
                return f"# Fallback query generation also failed: {str(fallback_error)}"

    def map_sigma_level_to_severity(self, level: str) -> str:
        """Map Sigma level to OpenTide severity"""
        level_map = {
            'informational': 'Informational',
            'low': 'Low',
            'medium': 'Medium',
            'high': 'High',
            'critical': 'Critical'
        }
        return level_map.get(level.lower(), 'Medium')

    def extract_mitre_techniques(self, sigma_rule: SigmaRule) -> List[str]:
        """Extract MITRE ATT&CK techniques from Sigma rule"""
        techniques = []
        
        # Check tags for MITRE techniques
        if hasattr(sigma_rule, 'tags') and sigma_rule.tags:
            for tag in sigma_rule.tags:
                tag_str = str(tag).lower()
                # Look for attack.t#### patterns
                if 'attack.t' in tag_str:
                    # Extract technique ID
                    match = re.search(r'attack\.t(\d+(?:\.\d+)?)', tag_str)
                    if match:
                        techniques.append(f"T{match.group(1)}")
        
        return techniques

    def determine_alert_category(self, sigma_rule: SigmaRule) -> Optional[str]:
        """Determine alert category from Sigma rule tags"""
        if not hasattr(sigma_rule, 'tags') or not sigma_rule.tags:
            return None
        
        # Map MITRE tactics to categories
        tactic_map = {
            'initial_access': 'InitialAccess',
            'execution': 'Execution', 
            'persistence': 'Persistence',
            'privilege_escalation': 'PrivilegeEscalation',
            'defense_evasion': 'DefenseEvasion',
            'credential_access': 'CredentialAccess',
            'discovery': 'Discovery',
            'lateral_movement': 'LateralMovement',
            'collection': 'Collection',
            'command_and_control': 'CommandAndControl',
            'exfiltration': 'Exfiltration',
            'impact': 'Impact'
        }
        
        for tag in sigma_rule.tags:
            tag_str = str(tag).lower()
            for tactic, category in tactic_map.items():
                if f'attack.{tactic}' in tag_str:
                    return category
        
        return None

    def create_defender_configuration(self, sigma_rule: SigmaRule, query: str) -> Dict[str, Any]:
        """Create Defender for Endpoint configuration"""
        config = {
            'schema': 'defender_for_endpoint::2.0',
            'status': 'DEVELOPMENT'
        }
        
        # Add alert configuration
        alert_config = {}
        if sigma_rule.title:
            alert_config['title'] = sigma_rule.title
        
        # Map severity from Sigma level
        if hasattr(sigma_rule, 'level') and sigma_rule.level:
            alert_config['severity'] = self.map_sigma_level_to_severity(str(sigma_rule.level))
        
        # Add MITRE techniques
        techniques = self.extract_mitre_techniques(sigma_rule)
        if techniques:
            alert_config['techniques'] = techniques
        
        # Determine category
        category = self.determine_alert_category(sigma_rule)
        if category:
            alert_config['category'] = category
        
        if alert_config:
            config['alert'] = alert_config
        
        # Add scope
        config['scope'] = {'selection': 'All'}
        
        # Add query
        config['query'] = query
        
        return config

    def create_splunk_configuration(self, sigma_rule: SigmaRule, query: str) -> Dict[str, Any]:
        """Create Splunk configuration"""
        config = {
            'schema': 'splunk::2.1',
            'status': 'DEVELOPMENT'
        }
        
        # Add query
        config['query'] = query
        
        return config

    def create_opentide_yaml(self, sigma_rule: SigmaRule, target_systems: Optional[List[str]] = None) -> Dict[str, Any]:
        """Create OpenTide YAML structure from Sigma rule"""
        if target_systems is None:
            target_systems = ['defender_for_endpoint', 'splunk']
        
        yaml_data = {}
        
        # Basic fields
        if sigma_rule.title:
            yaml_data['name'] = sigma_rule.title
        
        # References
        references = {}
        if hasattr(sigma_rule, 'references') and sigma_rule.references:
            public_refs = {}
            for i, ref in enumerate(sigma_rule.references, 1):
                public_refs[str(i)] = str(ref)
            references['public'] = public_refs
        
        if references:
            yaml_data['references'] = references
        
        # Metadata section
        metadata = {
            'schema': 'mdr::2.1',
            'version': 1,
            'tlp': 'amber+strict'
        }
        
        # Add UUID if available
        if hasattr(sigma_rule, 'id') and sigma_rule.id:
            metadata['uuid'] = str(sigma_rule.id)
        
        # Add dates
        if hasattr(sigma_rule, 'date') and sigma_rule.date:
            metadata['created'] = str(sigma_rule.date)
            metadata['modified'] = str(sigma_rule.date)
        else:
            today = datetime.now().strftime('%Y-%m-%d')
            metadata['created'] = today
            metadata['modified'] = today
        
        # Add author
        if hasattr(sigma_rule, 'author') and sigma_rule.author:
            metadata['author'] = str(sigma_rule.author)
        
        yaml_data['metadata'] = metadata
        
        # Description
        if sigma_rule.description:
            yaml_data['description'] = sigma_rule.description
        
        # Response section
        response = {}
        if hasattr(sigma_rule, 'level') and sigma_rule.level:
            response['alert_severity'] = self.map_sigma_level_to_severity(str(sigma_rule.level))
        
        yaml_data['response'] = response
        
        # Configurations section
        configurations = {}
        
        for target_system in target_systems:
            query = self.generate_query(sigma_rule, target_system)
            
            if target_system == 'defender_for_endpoint':
                configurations['defender_for_endpoint'] = self.create_defender_configuration(sigma_rule, query)
            elif target_system == 'splunk':
                configurations['splunk'] = self.create_splunk_configuration(sigma_rule, query)
        
        yaml_data['configurations'] = configurations
        
        return yaml_data

    def write_yaml_with_comments(self, yaml_data: Dict[str, Any], output_path: str) -> None:
        """Write YAML with proper commented structure"""
        lines = []
        
        # Name
        if 'name' in yaml_data:
            lines.append(f"name: {yaml_data['name']}")
        else:
            lines.append("name: ")
        
        lines.append("")
        
        # References
        if 'references' in yaml_data:
            lines.append("references:")
            references = yaml_data['references']
            if 'public' in references:
                lines.append("  public:")
                for key, value in references['public'].items():
                    lines.append(f"    {key}: {value}")
            else:
                lines.append("  #public:")
                lines.append("    #1: ")
            
            lines.append("  #internal:")
            lines.append("    #a: ")
        else:
            lines.append("#references:")
            lines.append("  #public:")
            lines.append("    #1: ")
            lines.append("  #internal:")
            lines.append("    #a: ")
        
        lines.append("")
        
        # Metadata
        lines.append("metadata:")
        metadata = yaml_data.get('metadata', {})
        
        if 'uuid' in metadata:
            lines.append(f"  uuid: {metadata['uuid']}")
        else:
            lines.append("  #uuid: ")
        
        lines.append(f"  schema: {metadata.get('schema', 'mdr::2.1')}")
        lines.append(f"  version: {metadata.get('version', 1)}")
        lines.append(f"  created: {metadata.get('created', '')}")
        lines.append(f"  modified: {metadata.get('modified', '')}")
        lines.append(f"  tlp: {metadata.get('tlp', 'amber+strict')}")
        
        if 'author' in metadata:
            lines.append(f"  author: {metadata['author']}")
        else:
            lines.append("  #author: ")
        
        lines.append("  #contributors:")
        lines.append("    #-")
        lines.append("  #organisation:")
        lines.append("    #uuid: ")
        lines.append("    #name: ")
        lines.append("")
        
        # Description
        if 'description' in yaml_data:
            lines.append("description: |")
            description = yaml_data['description']
            for line in description.split('\n'):
                lines.append(f"  {line}")
        else:
            lines.append("description: |")
            lines.append("  ...")
        lines.append("")
        
        # Detection model (commented)
        lines.append("#detection_model: ")
        lines.append("")
        
        # Response
        lines.append("response:")
        response = yaml_data.get('response', {})
        if 'alert_severity' in response:
            lines.append(f"  alert_severity: {response['alert_severity']}")
        else:
            lines.append("  alert_severity: ")
        lines.append("  #playbook: https://")
        lines.append("  #responders: ")
        lines.append("")
        
        # Configurations
        lines.append("configurations:")
        configurations = yaml_data.get('configurations', {})
        
        for system_name, config in configurations.items():
            lines.append(f"  {system_name}:")
            
            # Schema and status
            if 'schema' in config:
                lines.append(f"    schema: {config['schema']}")
            if 'status' in config:
                lines.append(f"    status: {config['status']}")
            
            # Commented fields
            lines.append("    #contributors:")
            lines.append("      #-")
            lines.append("    #tenants:")
            lines.append("      #-")
            lines.append("    #flags:")
            lines.append("      #-")
            lines.append("")
            
            # Scheduling (commented - needs manual completion)
            lines.append("    #scheduling:")
            if system_name == 'splunk':
                lines.append("      #cron: # MANUAL COMPLETION REQUIRED")
                lines.append("      #frequency: # MANUAL COMPLETION REQUIRED")
                lines.append("      #custom_time: # MANUAL COMPLETION REQUIRED")
                lines.append("      #lookback: # MANUAL COMPLETION REQUIRED")
            else:
                lines.append("      #frequency: # MANUAL COMPLETION REQUIRED")
                lines.append("      #lookback: # MANUAL COMPLETION REQUIRED")
            lines.append("")
            
            # System-specific configurations
            if system_name == 'defender_for_endpoint':
                self._write_defender_config(lines, config)
            elif system_name == 'splunk':
                self._write_splunk_config(lines, config)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))

    def _write_defender_config(self, lines: List[str], config: Dict[str, Any]) -> None:
        """Write Defender for Endpoint specific configuration"""
        # Alert section
        lines.append("    alert:")
        alert = config.get('alert', {})
        
        if 'title' in alert:
            lines.append(f"      title: \"{alert['title']}\"")
        else:
            lines.append("      #title: ")
            
        if 'category' in alert:
            lines.append(f"      category: {alert['category']}")
        else:
            lines.append("      #category: ")
            
        if 'techniques' in alert and alert['techniques']:
            lines.append("      techniques:")
            for technique in alert['techniques']:
                lines.append(f"        - {technique}")
        else:
            lines.append("      #techniques:")
            lines.append("        #-")
            
        if 'severity' in alert:
            lines.append(f"      severity: {alert['severity']}")
        else:
            lines.append("      #severity: ")
            
        lines.append("      #recommendation: |")
        lines.append("        #...")
        lines.append("")
        
        # Impacted entities (needs manual completion)
        lines.append("    impacted_entities:")
        lines.append("      #device: # MANUAL COMPLETION REQUIRED")
        lines.append("      #mailbox: # MANUAL COMPLETION REQUIRED")
        lines.append("      #user: # MANUAL COMPLETION REQUIRED")
        lines.append("")
        
        # Actions (commented)
        lines.append("    #actions:")
        lines.append("      #devices:")
        lines.append("        #isolate_device: ")
        lines.append("        #collect_investigation_package: false")
        lines.append("        #run_antivirus_scan: false")
        lines.append("        #initiate_investigation: false")
        lines.append("        #restrict_app_execution: false")
        lines.append("      #files:")
        lines.append("        #allow_block:")
        lines.append("          #action: ")
        lines.append("          #identifier: ")
        lines.append("      #users:")
        lines.append("        #mark_as_compromised: ")
        lines.append("        #disable_user: ")
        lines.append("        #force_password_reset: ")
        lines.append("")
        
        # Scope
        lines.append("    scope:")
        scope = config.get('scope', {})
        if 'selection' in scope:
            lines.append(f"      selection: {scope['selection']}")
        else:
            lines.append("      selection: All")
        lines.append("      #device_groups:")
        lines.append("        #-")
        lines.append("")
        
        # Query
        if 'query' in config:
            lines.append("    query: |")
            for line in config['query'].split('\n'):
                lines.append(f"      {line}")
        else:
            lines.append("    query: |")
            lines.append("      ...")
        lines.append("")
        
        # Exclusions (commented)
        lines.append("    #exclusions:")
        lines.append("      #- tenant: ")
        lines.append("        #reason: |")
        lines.append("          #...")

    def _write_splunk_config(self, lines: List[str], config: Dict[str, Any]) -> None:
        """Write Splunk specific configuration"""
        # Additional Splunk-specific fields (commented)
        lines.append("    #threshold: 0")
        lines.append("")
        lines.append("    #throttling:")
        lines.append("      #fields:")
        lines.append("        #-")
        lines.append("      #duration: 1h")
        lines.append("")
        lines.append("    #notable:")
        lines.append("      #event:")
        lines.append("        #title: ")
        lines.append("        #description: |")
        lines.append("          #...")
        lines.append("      #drilldown:")
        lines.append("        #name: ")
        lines.append("        #search: |")
        lines.append("          #...")
        lines.append("      #security_domain: ")
        lines.append("")
        lines.append("    #risk:")
        lines.append("      #message: ")
        lines.append("      #risk_objects:")
        lines.append("        #- field: ")
        lines.append("          #type: ")
        lines.append("          #score: ")
        lines.append("      #threat_objects:")
        lines.append("        #- field: ")
        lines.append("          #type: ")
        lines.append("")
        
        # Query
        if 'query' in config:
            lines.append("    query: |")
            for line in config['query'].split('\n'):
                lines.append(f"      {line}")
        else:
            lines.append("    query: |")
            lines.append("      ...")

    def convert_file(self, input_path: str, output_path: str, target_systems: Optional[List[str]] = None) -> bool:
        """Convert a single Sigma rule file to OpenTide format"""
        try:
            print(f"Converting {input_path}...")
            
            # Parse the Sigma rule
            sigma_rule = self.parse_sigma_rule(input_path)
            
            # Create OpenTide YAML
            yaml_data = self.create_opentide_yaml(sigma_rule, target_systems)
            
            # Write with comments
            self.write_yaml_with_comments(yaml_data, output_path)
            
            print(f"✓ Successfully converted to {output_path}")
            print("⚠ IMPORTANT: Manual completion required for:")
            print("   - Scheduling configuration (frequency, lookback)")
            print("   - Impacted entities (device, user, mailbox)")
            return True
            
        except Exception as e:
            print(f"✗ Error converting {input_path}: {str(e)}")
            return False

    def convert_directory(self, input_dir: str, output_dir: str, target_systems: Optional[List[str]] = None) -> int:
        """Convert all Sigma rule files in a directory"""
        input_path = Path(input_dir)
        output_path = Path(output_dir)
        
        # Create output directory if it doesn't exist
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Find all YAML files
        yaml_files = list(input_path.glob("*.yml")) + list(input_path.glob("*.yaml"))
        
        if not yaml_files:
            print(f"No YAML files found in {input_dir}")
            return 0
        
        successful_conversions = 0
        
        for yaml_file in yaml_files:
            output_file = output_path / f"{yaml_file.stem}_opentide.yaml"
            if self.convert_file(str(yaml_file), str(output_file), target_systems):
                successful_conversions += 1
        
        print(f"\nConversion complete: {successful_conversions}/{len(yaml_files)} files converted successfully")
        return successful_conversions