#!/usr/bin/env python3
import sys
import re
import json
import shutil
import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Set, Tuple
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
import textwrap
import os

VERSION = "1.1"
AUTHOR = "Sandeep Wawdane"
ANDROID = "http://schemas.android.com/apk/res/android"
console = Console()

@dataclass
class IntentExtra:
    name: str
    type: str
    required: bool = False
    default_value: Optional[str] = None
    
    def to_dict(self):
        return {
            "name": self.name,
            "type": self.type,
            "required": self.required,
            "default_value": self.default_value,
        }

class SmaliAnalyzer:
    def __init__(self, decompiled_dir: str, verbose: bool = False, quiet: bool = False):
        self.decompiled_dir = Path(decompiled_dir)
        self.verbose = verbose
        self.quiet = quiet
        self.string_pool: Dict[str, str] = {}
        
    def find_smali_files(self, class_name: str) -> List[Path]:
        base_path = class_name.replace('.', '/')
        files = []
        patterns = [
            f"{base_path}.smali",
            f"{base_path}$*.smali"
        ]
        for smali_dir in self.decompiled_dir.glob('smali*'):
            for pattern in patterns:
                files.extend(smali_dir.glob(pattern))
        return files

    def _extract_string_pool(self, content: str) -> Dict[str, str]:
        strings = {}
        for match in re.finditer(r'const-string(?:/jumbo)?\s+v(\d+),\s+"([^"\\]*(?:\\.[^"\\]*)*)"', content):
            reg = match.group(1)
            value = match.group(2)
            value = value.replace('\\"', '"').replace('\\n', '\n').replace('\\t', '\t')
            strings[reg] = value
        return strings

    def _is_valid_extra_name(self, name: str) -> bool:
        invalid_patterns = [
            r'^[A-Z][a-z]+.*[.!?]$',
            r'^\s*$',
            r'^.{50,}$',
            r'https?://',
            r'www\.',
            r'^Error:',
            r'^Exception',
            r'null!',
            r'was null',
            r'callback',
            r'Executor',
        ]
        valid_patterns = [
            r'^[a-zA-Z_][a-zA-Z0-9_]*$',
            r'^[a-z]+[_.]?[a-z]+$',
            r'^[a-z]+[A-Z][a-zA-Z]*$',
            r'^[A-Z]+_[A-Z]+$',
        ]
        for pattern in invalid_patterns:
            if re.search(pattern, name, re.IGNORECASE):
                return False
        for pattern in valid_patterns:
            if re.match(pattern, name):
                return True
        if len(name) < 2 or len(name) > 40:
            return False
        if ' ' in name and not any(re.match(p, name) for p in valid_patterns):
            return False
        return True

    def _extract_extras_from_method(self, content: str, method_name: str) -> Dict[str, IntentExtra]:
        extras: Dict[str, IntentExtra] = {}
        method_pattern = rf'\.method\s+.*?\s+{method_name}\s*\([^)]*\).*?^\.end method'
        method_match = re.search(method_pattern, content, re.MULTILINE | re.DOTALL)
        if not method_match:
            return extras
        method_body = method_match.group(0)
        strings = self._extract_string_pool(method_body)
        extra_patterns = [
            (r'getStringExtra', 'string'),
            (r'getBooleanExtra', 'boolean'),
            (r'getIntExtra', 'int'),
            (r'getLongExtra', 'long'),
            (r'getFloatExtra', 'float'),
            (r'getDoubleExtra', 'double'),
            (r'getByteExtra', 'byte'),
            (r'getShortExtra', 'short'),
            (r'getCharExtra', 'char'),
            (r'getStringArrayExtra', 'string[]'),
            (r'getIntArrayExtra', 'int[]'),
            (r'getByteArrayExtra', 'byte[]'),
            (r'getCharArrayExtra', 'char[]'),
            (r'getFloatArrayExtra', 'float[]'),
            (r'getDoubleArrayExtra', 'double[]'),
            (r'getLongArrayExtra', 'long[]'),
            (r'getShortArrayExtra', 'short[]'),
            (r'getBooleanArrayExtra', 'boolean[]'),
            (r'getBundleExtra', 'bundle'),
            (r'getParcelableExtra', 'parcelable'),
            (r'getSerializableExtra', 'serializable'),
            (r'getStringArrayListExtra', 'ArrayList<String>'),
            (r'getIntegerArrayListExtra', 'ArrayList<Integer>'),
            (r'getParcelableArrayListExtra', 'ArrayList<Parcelable>'),
            (r'getCharSequenceExtra', 'CharSequence'),
            (r'getCharSequenceArrayExtra', 'CharSequence[]'),
            (r'getCharSequenceArrayListExtra', 'ArrayList<CharSequence>'),
        ]
        for extra_method, extra_type in extra_patterns:
            pattern = rf'invoke-virtual\s+\{{([^}}]+)\}},\s*Landroid/content/Intent;->{extra_method}'
            for match in re.finditer(pattern, method_body):
                regs = match.group(1).split(',')
                if len(regs) < 2:
                    continue
                intent_reg = regs[0].strip()
                key_reg = regs[1].strip()
                if key_reg.startswith('v') and key_reg[1:] in strings:
                    key = strings[key_reg[1:]]
                    if not self._is_valid_extra_name(key):
                        continue
                    pos = match.end()
                    next_lines = method_body[pos:pos+200]
                    required = False
                    default_value = None
                    if 'move-result' in next_lines:
                        if re.search(r'if-(?:eq|ne)z\s+v\d+', next_lines):
                            required = True
                    if extra_type in ['boolean', 'int', 'long', 'float', 'double', 'byte', 'short', 'char']:
                        if len(regs) > 2:
                            default_reg = regs[2].strip()
                            if default_reg.startswith('v') and default_reg[1:] in strings:
                                default_value = strings[default_reg[1:]]
                            elif re.match(r'^-?\d+$', default_reg):
                                default_value = default_reg
                    if key not in extras or required:
                        extras[key] = IntentExtra(
                            name=key,
                            type=extra_type,
                            required=required,
                            default_value=default_value
                        )
        if 'getExtras()' in method_body:
            bundle_pattern = r'invoke-virtual\s+\{([^}]+)\},\s*Landroid/os/Bundle;->get(\w+)'
            for match in re.finditer(bundle_pattern, method_body):
                regs = match.group(1).split(',')
                if len(regs) >= 2:
                    key_reg = regs[1].strip()
                    method_type = match.group(2)
                    if key_reg.startswith('v') and key_reg[1:] in strings:
                        key = strings[key_reg[1:]]
                        if not self._is_valid_extra_name(key):
                            continue
                        type_map = {
                            'String': 'string',
                            'Boolean': 'boolean',
                            'Int': 'int',
                            'Long': 'long',
                            'Float': 'float',
                            'Double': 'double',
                            'Byte': 'byte',
                            'Short': 'short',
                            'Char': 'char',
                            'Bundle': 'bundle',
                            'Parcelable': 'parcelable',
                            'Serializable': 'serializable',
                            'StringArray': 'string[]',
                            'IntArray': 'int[]',
                            'StringArrayList': 'ArrayList<String>',
                            'IntegerArrayList': 'ArrayList<Integer>',
                            'ParcelableArrayList': 'ArrayList<Parcelable>',
                        }
                        if method_type in type_map:
                            extras[f"bundle.{key}"] = IntentExtra(
                                name=key,
                                type=f"bundle.{type_map[method_type]}",
                                required=False
                            )
        return extras

    def _analyze_content_provider_operations(self, smali_files: List[Path]) -> Dict[str, Any]:
        operations = {
            'uri_patterns': set(),
            'paths': set(),
            'operations': set(),
            'tables': set(),
            'columns': set()
        }
        
        for smali_file in smali_files:
            try:
                content = smali_file.read_text(encoding='utf-8')
            except:
                continue
                
            uri_matches = re.findall(r'content://[^"\s]+', content)
            operations['uri_patterns'].update(uri_matches)
            
            path_matches = re.findall(r'"/[^"\s]+"', content)
            for path in path_matches:
                path = path.strip('"')
                if len(path) > 1 and not path.startswith('/android') and not path.startswith('/system'):
                    operations['paths'].add(path)
            
            table_patterns = [
                r'"(\w+_table)"',
                r'"(\w+s)"',
                r'TABLE_(\w+)',
                r'"tbl_(\w+)"'
            ]
            for pattern in table_patterns:
                table_matches = re.findall(pattern, content)
                operations['tables'].update(table_matches)
            
            column_patterns = [
                r'"(_id)"',
                r'"(\w+_id)"',
                r'"(\w+_name)"',
                r'"(\w+_date)"',
                r'"(\w+_time)"',
                r'COLUMN_(\w+)',
            ]
            for pattern in column_patterns:
                col_matches = re.findall(pattern, content)
                operations['columns'].update(col_matches)
            
            for op in ['query', 'insert', 'update', 'delete']:
                if f'ContentResolver;->{op}' in content or f'ContentProvider;->{op}' in content:
                    operations['operations'].add(op)
                    
        return {
            'uri_patterns': list(operations['uri_patterns']),
            'paths': list(operations['paths']),
            'operations': list(operations['operations']),
            'tables': list(operations['tables']),
            'columns': list(operations['columns'])
        }

    def analyze_component(self, class_name: str, component_type: str) -> Dict[str, Any]:
        result = {
            'extras': {},
        }
        
        smali_files = self.find_smali_files(class_name)
        if not smali_files:
            if self.verbose and not self.quiet:
                console.print(f"[yellow]Warning: No smali files found for {class_name}[/yellow]")
            return result
            
        methods_to_analyze = {
            'activity': ['onCreate', 'onStart', 'onResume', 'onNewIntent', 'onActivityResult', 
                        'onSaveInstanceState', 'onRestoreInstanceState', 'handleIntent', 'processIntent'],
            'service': ['onCreate', 'onStartCommand', 'onBind', 'onHandleIntent', 'onStart', 
                       'handleIntent', 'processIntent'],
            'receiver': ['onReceive', 'handleIntent', 'processIntent'],
            'provider': ['onCreate', 'query', 'insert', 'update', 'delete', 'getType', 'call',
                        'openFile', 'openAssetFile']
        }.get(component_type, [])
        
        for smali_file in smali_files:
            try:
                content = smali_file.read_text(encoding='utf-8')
                
                for method in methods_to_analyze:
                    extras = self._extract_extras_from_method(content, method)
                    for key, extra in extras.items():
                        result['extras'][key] = extra.to_dict()
                    
            except Exception as e:
                if self.verbose:
                    console.print(f"[red]Error analyzing {smali_file}: {e}[/red]")
                    
        if component_type == 'provider':
            provider_ops = self._analyze_content_provider_operations(smali_files)
            result['provider_operations'] = provider_ops
            
        return result

class APKAnalyzer:
    def __init__(self, apk_path: str, verbose: bool = False, quiet: bool = False, cleanup: bool = False, all_activities: bool = False):
        self.apk_path = Path(apk_path)
        self.verbose = verbose
        self.quiet = quiet
        self.cleanup = cleanup
        self.all_activities = all_activities
        self.decompiled_dir: Optional[Path] = None
        self.smali: Optional[SmaliAnalyzer] = None
        self.success = False
        
        try:
            from androguard.core.bytecodes.apk import APK
            self.apk = APK(str(self.apk_path))
        except ImportError:
            console.print("[bold red]Error:[/] Incorrect androguard version detected!", style="bold red")
            console.print("[yellow]This script requires androguard version 3.3.5 specifically.[/]")
            console.print("[yellow]Newer versions (4.x+) have incompatible API changes.[/]")
            console.print("")
            console.print("[cyan]Fix:[/] pip3 uninstall androguard && pip3 install androguard==3.3.5")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Error loading APK:[/] {e}", style="bold red")
            sys.exit(1)
            
        self.package = self.apk.get_package()

    def _check_tools(self):
        if shutil.which('apktool') is None:
            console.print("[bold red]Error:[/] apktool not found in PATH", style="bold red")
            sys.exit(1)
                
    def decompile(self) -> bool:
        apk_name = self.apk_path.stem
        self.decompiled_dir = self.apk_path.parent / f"{apk_name}_decompiled"
        
        if self.decompiled_dir.exists():
            shutil.rmtree(self.decompiled_dir)
            
        if not self.quiet:
            console.print(f"Decompiling {self.apk_path.name}...", style="white")
            
        cmd = ["apktool", "d", "-f", str(self.apk_path), "-o", str(self.decompiled_dir)]
        if not self.verbose:
            cmd.append("-q")
            
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            console.print(f"[bold red]Decompilation failed:[/]\n{result.stderr}", style="red")
            return False
            
        manifest = self.decompiled_dir / 'AndroidManifest.xml'
        if not manifest.exists():
            console.print("[bold red]Error:[/] AndroidManifest.xml not found after decompilation", style="bold red")
            return False
            
        if not any(self.decompiled_dir.glob('smali*/**/*.smali')):
            console.print("[bold red]Error:[/] No smali files found", style="bold red")
            return False
            
        if not self.quiet:
            console.print(f"✓ Successfully decompiled to {self.decompiled_dir.name}", style="green")
            
        self.smali = SmaliAnalyzer(str(self.decompiled_dir), verbose=self.verbose, quiet=self.quiet)
        return True

    def parse_manifest(self) -> Dict[str, Any]:
        data = {
            'activities': [],
            'services': [],
            'receivers': [],
            'providers': []
        }
        
        manifest_path = self.decompiled_dir / 'AndroidManifest.xml'
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
        except ET.ParseError as e:
            console.print(f"[bold red]Error parsing manifest:[/] {e}", style="red")
            return {'error': f'Manifest parse error: {e}'}
            
        app = root.find('.//application')
        if app is None:
            return data
                
        component_types = [
            ('activity', 'activities'),
            ('activity-alias', 'activities'),
            ('service', 'services'),
            ('receiver', 'receivers'),
            ('provider', 'providers')
        ]
        
        for elem_type, data_key in component_types:
            for elem in app.findall(f'.//{elem_type}'):
                comp_info = self._extract_component_info(elem, elem_type.replace('-alias', ''))
                if comp_info:
                    is_exported = self._is_component_exported(comp_info, elem_type.replace('-alias', ''))
                    comp_info['is_exported'] = is_exported
                    
                    if is_exported:
                        data[data_key].append(comp_info)
                    elif self.all_activities and data_key == 'activities':
                        data[data_key].append(comp_info)
                    
        return data

    def _extract_component_info(self, elem: ET.Element, comp_type: str) -> Optional[Dict[str, Any]]:
        if elem.tag == 'activity-alias':
            name = elem.get(f'{{{ANDROID}}}targetActivity')
        else:
            name = elem.get(f'{{{ANDROID}}}name')
            
        if not name:
            return None
            
        if name.startswith('.'):
            name = self.package + name
        elif '.' not in name:
            name = f"{self.package}.{name}"
            
        info = {
            'name': name,
            'exported': elem.get(f'{{{ANDROID}}}exported'),
            'permission': elem.get(f'{{{ANDROID}}}permission'),
            'intent_filters': [],
        }
        
        if comp_type == 'activity':
            info['launchMode'] = elem.get(f'{{{ANDROID}}}launchMode', 'standard')
            info['taskAffinity'] = elem.get(f'{{{ANDROID}}}taskAffinity')
            info['allowTaskReparenting'] = elem.get(f'{{{ANDROID}}}allowTaskReparenting', 'false') == 'true'
            info['clearTaskOnLaunch'] = elem.get(f'{{{ANDROID}}}clearTaskOnLaunch', 'false') == 'true'
            
        elif comp_type == 'service':
            info['process'] = elem.get(f'{{{ANDROID}}}process')
            info['enabled'] = elem.get(f'{{{ANDROID}}}enabled', 'true') == 'true'
            
        elif comp_type == 'receiver':
            info['enabled'] = elem.get(f'{{{ANDROID}}}enabled', 'true') == 'true'
            info['process'] = elem.get(f'{{{ANDROID}}}process')
            
        elif comp_type == 'provider':
            authorities = elem.get(f'{{{ANDROID}}}authorities', '')
            info['authorities'] = [a.strip() for a in authorities.split(';') if a.strip()]
            info['grantUriPermissions'] = elem.get(f'{{{ANDROID}}}grantUriPermissions', 'false') == 'true'
            info['readPermission'] = elem.get(f'{{{ANDROID}}}readPermission')
            info['writePermission'] = elem.get(f'{{{ANDROID}}}writePermission')
            info['multiprocess'] = elem.get(f'{{{ANDROID}}}multiprocess', 'false') == 'true'
            
            path_perms = []
            for path_perm in elem.findall('.//path-permission'):
                perm_info = {
                    'path': path_perm.get(f'{{{ANDROID}}}path'),
                    'pathPrefix': path_perm.get(f'{{{ANDROID}}}pathPrefix'),
                    'pathPattern': path_perm.get(f'{{{ANDROID}}}pathPattern'),
                }
                if any(perm_info.values()):
                    path_perms.append(perm_info)
                    
            if path_perms:
                info['pathPermissions'] = path_perms
                
            grant_uris = []
            for grant in elem.findall('.//grant-uri-permission'):
                grant_info = {
                    'path': grant.get(f'{{{ANDROID}}}path'),
                    'pathPrefix': grant.get(f'{{{ANDROID}}}pathPrefix'),
                    'pathPattern': grant.get(f'{{{ANDROID}}}pathPattern'),
                }
                if any(grant_info.values()):
                    grant_uris.append(grant_info)
                    
            if grant_uris:
                info['grantUriPatterns'] = grant_uris
                
        for intent_filter in elem.findall('.//intent-filter'):
            filter_info = self._extract_intent_filter(intent_filter)
            if filter_info and (filter_info['actions'] or filter_info['data']):
                info['intent_filters'].append(filter_info)
                
        return info

    def _extract_intent_filter(self, intent_filter: ET.Element) -> Dict[str, List]:
        filter_data = {
            'actions': [],
            'categories': [],
            'data': []
        }
        
        for action in intent_filter.findall('.//action'):
            action_name = action.get(f'{{{ANDROID}}}name')
            if action_name:
                filter_data['actions'].append(action_name)
                
        for category in intent_filter.findall('.//category'):
            cat_name = category.get(f'{{{ANDROID}}}name')
            if cat_name:
                filter_data['categories'].append(cat_name)
                
        for data in intent_filter.findall('.//data'):
            data_info = {}
            attrs = ['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'mimeType']
            for attr in attrs:
                value = data.get(f'{{{ANDROID}}}{attr}')
                if value:
                    data_info[attr] = value
            if data_info:
                filter_data['data'].append(data_info)
                
        return filter_data

    def _is_component_exported(self, comp_info: Dict[str, Any], comp_type: str) -> bool:
        exported = comp_info.get('exported')
        
        if exported is not None:
            return exported.lower() == 'true'
            
        if not comp_info.get('enabled', True):
            return False
            
        if comp_info['intent_filters']:
            for filter in comp_info['intent_filters']:
                if filter['actions']:
                    return True
            return False
            
        if comp_type == 'provider':
            return comp_info.get('grantUriPermissions', False) or bool(comp_info.get('grantUriPatterns'))
            
        return False

    def analyze_components(self, manifest_data: Dict[str, Any]) -> Dict[str, Any]:
        if 'error' in manifest_data:
            return manifest_data
            
        results = {
            'package': self.package,
            'components': {
                'activities': [],
                'services': [],
                'receivers': [],
                'providers': []
            }
        }
        
        comp_types = [
            ('activities', 'activity'),
            ('services', 'service'),
            ('receivers', 'receiver'),
            ('providers', 'provider')
        ]
        
        for data_key, comp_type in comp_types:
            for comp in manifest_data.get(data_key, []):
                if not self.quiet:
                    export_status = "exported" if comp.get('is_exported', False) else "non-exported"
                    console.print(f"Analyzing {comp_type} ({export_status}): {comp['name']}", style="cyan")
                    
                analysis = {
                    'name': comp['name'],
                    'permission': comp.get('permission'),
                    'intent_filters': comp.get('intent_filters', []),
                    'is_exported': comp.get('is_exported', False)
                }
                
                if comp_type == 'activity':
                    analysis['launchMode'] = comp.get('launchMode', 'standard')
                elif comp_type == 'service':
                    analysis['process'] = comp.get('process')
                elif comp_type == 'provider':
                    analysis['authorities'] = comp.get('authorities', [])
                    analysis['grantUriPermissions'] = comp.get('grantUriPermissions', False)
                    if comp.get('pathPermissions'):
                        analysis['pathPermissions'] = comp['pathPermissions']
                    if comp.get('grantUriPatterns'):
                        analysis['grantUriPatterns'] = comp['grantUriPatterns']
                    
                smali_results = self.smali.analyze_component(comp['name'], comp_type)
                
                if smali_results.get('extras'):
                    analysis['extras'] = smali_results['extras']
                    
                if comp_type == 'provider' and 'provider_operations' in smali_results:
                    analysis['operations'] = smali_results['provider_operations']
                    
                results['components'][data_key].append(analysis)
                
        return results

    def generate_exploits(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        if 'error' in analysis:
            return []
            
        exploits = []
        pkg = self.package
        
        for act in analysis['components']['activities']:
            exploits.extend(self._generate_activity_exploits(act, pkg))
            
        for svc in analysis['components']['services']:
            exploits.extend(self._generate_service_exploits(svc, pkg))
            
        for rcv in analysis['components']['receivers']:
            exploits.extend(self._generate_receiver_exploits(rcv, pkg))
            
        for prv in analysis['components']['providers']:
            exploits.extend(self._generate_provider_exploits(prv, pkg))
            
        return exploits

    def _generate_activity_exploits(self, activity: Dict[str, Any], pkg: str) -> List[Dict[str, Any]]:
        exploits = []
        name = activity['name']
        is_exported = activity.get('is_exported', False)
        
        if activity.get('permission') and is_exported:
            if not self.quiet:
                console.print(f"[yellow]Note: Activity {name} requires permission {activity['permission']}.[/yellow]")
            
        if not is_exported:
            exploits.append({
                'component': name,
                'command': f"adb shell su -c \"am start -n {pkg}/{name}\"",
                'description': 'Elevated privileges required'
            })
            
            if activity.get('extras'):
                cmd = f"adb shell su -c \"am start -n {pkg}/{name}"
                extra_desc = []
                
                for extra_name, extra_info in activity['extras'].items():
                    extra_cmd, desc = self._generate_extra_flag(extra_name, extra_info)
                    if not extra_cmd.startswith('#'):
                        cmd += f" {extra_cmd}"
                        extra_desc.append(desc)
                        
                if extra_desc:
                    cmd += "\""
                    exploits.append({
                        'component': name,
                        'command': cmd,
                        'description': f'Extras: {", ".join(extra_desc)}'
                    })
            
            return exploits
            
        base_cmd = f"adb shell am start -n {pkg}/{name}"
        
        has_useful_filters = False
        for filter in activity.get('intent_filters', []):
            if filter.get('actions'):
                has_useful_filters = True
                break
            
        if not has_useful_filters and not activity.get('extras'):
            exploits.append({
                'component': name,
                'command': base_cmd,
                'description': ''
            })
        
        for filter in activity.get('intent_filters', []):
            for action in filter.get('actions', []):
                cmd = f"{base_cmd} -a {action}"
                
                for cat in filter.get('categories', []):
                    if cat != 'android.intent.category.DEFAULT':
                        cmd += f" -c {cat}"
                        
                if filter.get('data'):
                    for data_elem in filter['data']:
                        data_uri = self._build_data_uri(data_elem)
                        if data_uri:
                            data_cmd = f'{cmd} -d "{data_uri}"'
                            exploits.append({
                                'component': name,
                                'command': data_cmd,
                                'description': f'Action: {action} + data'
                            })
                else:
                    exploits.append({
                        'component': name,
                        'command': cmd,
                        'description': f'Action: {action}'
                    })
                    
        if activity.get('extras'):
            cmd = base_cmd
            extra_desc = []
            
            for extra_name, extra_info in activity['extras'].items():
                extra_cmd, desc = self._generate_extra_flag(extra_name, extra_info)
                if not extra_cmd.startswith('#'):
                    cmd += f" {extra_cmd}"
                    extra_desc.append(desc)
                    
            if extra_desc:
                exploits.append({
                    'component': name,
                    'command': cmd,
                    'description': f'Extras: {", ".join(extra_desc)}'
                })
                
        if activity.get('launchMode') not in ['standard', None]:
            launch_mode = activity['launchMode']
            flags = {
                'singleTop': '--activity-single-top',
                'singleTask': '--activity-clear-task',
                'singleInstance': '--activity-clear-task --activity-new-task'
            }
            if launch_mode in flags:
                cmd = f"{base_cmd} {flags[launch_mode]}"
                exploits.append({
                    'component': name,
                    'command': cmd,
                    'description': f'{launch_mode} mode'
                })
                
        return exploits

    def _generate_service_exploits(self, service: Dict[str, Any], pkg: str) -> List[Dict[str, Any]]:
        exploits = []
        name = service['name']
        
        if service.get('permission'):
            if not self.quiet:
                console.print(f"[yellow]Note: Service {name} requires permission {service['permission']}, skipping.[/yellow]")
            return exploits
            
        base_cmd = f"adb shell am startservice -n {pkg}/{name}"
        
        if not service.get('intent_filters'):
            exploits.append({
                'component': name,
                'command': base_cmd,
                'description': ''
            })
        
        for filter in service.get('intent_filters', []):
            for action in filter.get('actions', []):
                cmd = f"{base_cmd} -a {action}"
                
                if filter.get('data'):
                    for data_elem in filter['data']:
                        data_uri = self._build_data_uri(data_elem)
                        if data_uri:
                            data_cmd = f'{cmd} -d "{data_uri}"'
                            exploits.append({
                                'component': name,
                                'command': data_cmd,
                                'description': f'Action: {action} + data'
                            })
                else:
                    exploits.append({
                        'component': name,
                        'command': cmd,
                        'description': f'Action: {action}'
                    })
                
        if service.get('extras'):
            cmd = base_cmd
            extra_descs = []
            
            if service.get('intent_filters'):
                for filter in service['intent_filters']:
                    if filter.get('actions'):
                        cmd += f" -a {filter['actions'][0]}"
                        break
                        
            for extra_name, extra_info in service['extras'].items():
                extra_cmd, desc = self._generate_extra_flag(extra_name, extra_info)
                if not extra_cmd.startswith('#'):
                    cmd += f" {extra_cmd}"
                    extra_descs.append(desc)
                    
            if extra_descs:
                exploits.append({
                    'component': name,
                    'command': cmd,
                    'description': f'Extras: {", ".join(extra_descs)}'
                })
                
        if not service.get('intent_filters'):
            exploits.append({
                'component': name,
                'command': f"adb shell am start-foreground-service -n {pkg}/{name}",
                'description': 'Foreground service'
            })
                
        return exploits

    def _generate_receiver_exploits(self, receiver: Dict[str, Any], pkg: str) -> List[Dict[str, Any]]:
        exploits = []
        name = receiver['name']
        
        if receiver.get('permission'):
            if not self.quiet:
                console.print(f"[yellow]Note: Receiver {name} requires permission {receiver['permission']}, skipping.[/yellow]")
            return exploits
            
        if not receiver.get('intent_filters'):
            exploits.append({
                'component': name,
                'command': f"adb shell am broadcast -n {pkg}/{name}",
                'description': ''
            })
            
        for filter in receiver.get('intent_filters', []):
            for action in filter.get('actions', []):
                cmd = f"adb shell am broadcast -a {action}"
                
                if self._is_custom_action(action):
                    cmd += f" -n {pkg}/{name}"
                    
                if filter.get('data'):
                    for data_elem in filter['data']:
                        data_uri = self._build_data_uri(data_elem)
                        if data_uri:
                            data_cmd = f'{cmd} -d "{data_uri}"'
                            exploits.append({
                                'component': name,
                                'command': data_cmd,
                                'description': f'{action} + data'
                            })
                else:
                    exploits.append({
                        'component': name,
                        'command': cmd,
                        'description': action
                    })
                    
        if receiver.get('extras'):
            if receiver.get('intent_filters'):
                for filter in receiver['intent_filters']:
                    if filter.get('actions'):
                        cmd = f"adb shell am broadcast -a {filter['actions'][0]}"
                        if self._is_custom_action(filter['actions'][0]):
                            cmd += f" -n {pkg}/{name}"
                        break
                else:
                    cmd = f"adb shell am broadcast -n {pkg}/{name}"
            else:
                cmd = f"adb shell am broadcast -n {pkg}/{name}"
                
            extra_descs = []
            for extra_name, extra_info in receiver['extras'].items():
                extra_cmd, desc = self._generate_extra_flag(extra_name, extra_info)
                if not extra_cmd.startswith('#'):
                    cmd += f" {extra_cmd}"
                    extra_descs.append(desc)
                    
            if extra_descs:
                exploits.append({
                    'component': name,
                    'command': cmd,
                    'description': f'Extras: {", ".join(extra_descs)}'
                })
                
        return exploits

    def _generate_provider_exploits(self, provider: Dict[str, Any], pkg: str) -> List[Dict[str, Any]]:
        exploits = []
        name = provider['name']
        
        if provider.get('permission'):
            if not self.quiet:
                console.print(f"[yellow]Note: Provider {name} requires permission {provider['permission']}, skipping.[/yellow]")
            return exploits
            
        for authority in provider.get('authorities', []):
            base_uri = f"content://{authority}"
            
            paths_to_test = []
            
            if 'pathPermissions' in provider:
                for path_perm in provider['pathPermissions']:
                    if path_perm.get('path'):
                        paths_to_test.append(path_perm['path'])
                    if path_perm.get('pathPrefix'):
                        paths_to_test.append(f"{path_perm['pathPrefix']}test")
                    if path_perm.get('pathPattern'):
                        pattern = path_perm['pathPattern']
                        example = pattern.replace('.*', 'test').replace('\\d+', '123').replace('\\', '')
                        paths_to_test.append(example)
                        
            if 'grantUriPatterns' in provider:
                for grant in provider['grantUriPatterns']:
                    if grant.get('path'):
                        paths_to_test.append(grant['path'])
                    if grant.get('pathPrefix'):
                        paths_to_test.append(f"{grant['pathPrefix']}test")
                        
            if 'operations' in provider:
                ops = provider['operations']
                if 'paths' in ops:
                    paths_to_test.extend(ops['paths'])
                    
                if 'tables' in ops:
                    for table in ops['tables']:
                        paths_to_test.append(f"/{table}")
                        
            if not paths_to_test:
                paths_to_test = ['']
                
                if 'operations' in provider and provider['operations'].get('operations'):
                    paths_to_test.extend(['/*', '/test', '/1'])
                    
            paths_to_test = list(set(p for p in paths_to_test if p is not None))
            
            for path in paths_to_test:
                uri = f"{base_uri}{path}"
                
                exploits.append({
                    'component': name,
                    'command': f'adb shell content query --uri "{uri}"',
                    'description': 'Query'
                })
                
                if 'operations' in provider and 'columns' in provider['operations']:
                    columns = list(provider['operations']['columns'])[:5]
                    if columns:
                        col_list = ':'.join(columns)
                        exploits.append({
                            'component': name,
                            'command': f'adb shell content query --uri "{uri}" --projection "{col_list}"',
                            'description': 'Query with columns'
                        })
                
                exploits.append({
                    'component': name,
                    'command': f'adb shell content query --uri "{uri}" --where "1=1--"',
                    'description': 'Query with injection payload'
                })
                
                if 'operations' in provider:
                    ops = provider['operations'].get('operations', [])
                    
                    if 'insert' in ops:
                        exploits.append({
                            'component': name,
                            'command': f'adb shell content insert --uri "{uri}" --bind name:s:test --bind value:s:data',
                            'description': f'Insert data'
                        })
                        
                    if 'update' in ops:
                        exploits.append({
                            'component': name,
                            'command': f'adb shell content update --uri "{uri}" --bind value:s:newdata --where "name=\'test\'"',
                            'description': f'Update data'
                        })
                        
                    if 'delete' in ops:
                        exploits.append({
                            'component': name,
                            'command': f'adb shell content delete --uri "{uri}" --where "name=\'test\'"',
                            'description': f'Delete data'
                        })
                        
            if provider.get('grantUriPermissions') or provider.get('grantUriPatterns'):
                uri = f"{base_uri}/test.txt"
                exploits.append({
                    'component': name,
                    'command': f'adb shell content read --uri "{uri}"',
                    'description': 'Read file'
                })
                exploits.append({
                    'component': name,
                    'command': f'echo "test data" | adb shell content write --uri "{uri}"',
                    'description': 'Write file'
                })
                        
        return exploits

    def _build_data_uri(self, data_elem: Dict[str, str]) -> str:
        scheme = data_elem.get('scheme', '')
        host = data_elem.get('host', '')
        port = data_elem.get('port', '')
        path = data_elem.get('path', '')
        path_prefix = data_elem.get('pathPrefix', '')
        path_pattern = data_elem.get('pathPattern', '')
        mime_type = data_elem.get('mimeType', '')
        
        if scheme and host:
            uri = f"{scheme}://{host}"
            if port:
                uri += f":{port}"
            if path:
                uri += path
            elif path_prefix:
                uri += f"{path_prefix}test"
            elif path_pattern:
                example = path_pattern.replace('.*', 'test').replace('\\d+', '123').replace('\\', '')
                uri += example
            return uri
        elif scheme:
            examples = {
                'tel': 'tel:+1234567890',
                'sms': 'sms:+1234567890',
                'smsto': 'smsto:+1234567890',
                'mailto': 'mailto:test@example.com',
                'geo': 'geo:0,0?q=test',
                'http': 'http://example.com',
                'https': 'https://example.com',
                'file': 'file:///sdcard/test.txt',
                'content': 'content://com.example.provider/test',
            }
            return examples.get(scheme, f"{scheme}://test")
        elif mime_type:
            if '/' in mime_type:
                ext = mime_type.split('/')[-1]
                if ext in ['jpeg', 'jpg', 'png', 'gif']:
                    return f"file:///sdcard/test.{ext}"
                elif ext == 'plain':
                    return "file:///sdcard/test.txt"
                else:
                    return f"file:///sdcard/test.{ext}"
            return "file:///sdcard/test"
        
        return ""

    def _generate_extra_flag(self, name: str, extra: Dict[str, Any]) -> Tuple[str, str]:
        if isinstance(extra, dict):
            extra_type = extra.get('type', '')
            default_value = extra.get('default_value')
        else:
            extra_type = extra.type
            default_value = extra.default_value
            
        display_name = name.replace('bundle.', '')
        
        type_map = {
            'string': ('--es', '"test_string"'),
            'boolean': ('--ez', 'true'),
            'int': ('--ei', '123'),
            'long': ('--el', '1234567890'),
            'float': ('--ef', '1.23'),
            'double': ('--ed', '1.234567'),
            'byte': ('--ei', '127'),
            'short': ('--ei', '32767'),
            'char': ('--ei', '65'),
            'string[]': ('--esa', 'item1,item2,item3'),
            'int[]': ('--eia', '1,2,3'),
            'byte[]': ('--eia', '1,2,3'),
            'char[]': ('--eia', '65,66,67'),
            'float[]': ('--efa', '1.1,2.2,3.3'),
            'double[]': ('--eda', '1.1,2.2,3.3'),
            'long[]': ('--ela', '100,200,300'),
            'short[]': ('--eia', '100,200,300'),
            'boolean[]': ('--eza', 'true,false,true'),
            'ArrayList<String>': ('--esal', 'item1,item2,item3'),
            'ArrayList<Integer>': ('--eial', '1,2,3'),
        }
        
        if extra_type.startswith('bundle.'):
            actual_type = extra_type.replace('bundle.', '')
            if actual_type in type_map:
                flag, value = type_map[actual_type]
                if default_value:
                    value = default_value
                return f"{flag} {display_name} {value}", f"{display_name}({actual_type})"
                
        if extra_type in type_map:
            flag, value = type_map[extra_type]
            if default_value:
                value = default_value
            return f"{flag} {display_name} {value}", f"{display_name}({extra_type})"
        else:
            return f"# Complex extra: {display_name} ({extra_type})", f"{display_name}({extra_type})[manual]"

    def _is_custom_action(self, action: str) -> bool:
        standard_prefixes = [
            'android.intent.action.',
            'android.app.action.',
            'android.bluetooth.',
            'android.net.',
            'android.nfc.',
            'android.provider.',
            'android.settings.',
            'android.media.',
            'android.service.',
            'android.speech.',
            'android.telephony.',
            'android.text.',
            'android.view.',
            'android.webkit.',
            'android.widget.',
            'com.android.',
            'com.google.android.',
        ]
        return not any(action.startswith(prefix) for prefix in standard_prefixes)

    def analyze(self) -> Dict[str, Any]:
        self._check_tools()
        
        if not self.decompile():
            return {'error': 'Decompilation failed'}
            
        if not self.quiet:
            console.print("Parsing AndroidManifest.xml...", style="white")
        manifest = self.parse_manifest()
        
        if 'error' in manifest:
            return manifest
            
        if not self.quiet:
            console.print("Analyzing components...", style="white")
        analysis = self.analyze_components(manifest)
        
        if 'error' in analysis:
            return analysis
            
        if not self.quiet:
            console.print("Generating exploits...", style="white")
        exploits = self.generate_exploits(analysis)
        
        analysis['exploits'] = exploits
        self.success = True
        
        return analysis

    def _format_adb_command(self, command: str, max_width: int = 80) -> str:
        """Format ADB command with proper line continuation for terminal compatibility"""
        if len(command) <= max_width:
            return command
            
        # Split command into parts
        parts = []
        current_part = ""
        in_quotes = False
        
        i = 0
        while i < len(command):
            char = command[i]
            
            if char == '"' and (i == 0 or command[i-1] != '\\'):
                in_quotes = not in_quotes
                
            current_part += char
            
            # Check if we should split here
            if not in_quotes and char == ' ' and len(current_part) > max_width - 10:
                parts.append(current_part.rstrip())
                current_part = ""
            
            i += 1
            
        if current_part:
            parts.append(current_part)
            
        # Join with line continuations
        if len(parts) > 1:
            formatted = parts[0]
            for part in parts[1:]:
                formatted += " \\\n    " + part.lstrip()
            return formatted
        else:
            return command

    def print_results(self, results: Dict[str, Any]):
        console.print(Rule(style="bright_cyan"))
        console.print(f"[bold bright_cyan]Package:[/] {results['package']}")
        
        total_exported = 0
        total_non_exported = 0
        
        for comp_type in results['components'].values():
            for comp in comp_type:
                if comp.get('is_exported', False):
                    total_exported += 1
                else:
                    total_non_exported += 1
                    
        console.print(f"[bold yellow]Exported Components:[/] {total_exported}")
        if self.all_activities and total_non_exported > 0:
            console.print(f"[bold magenta]Non-Exported Activities:[/] {total_non_exported}")
        
        total = total_exported + (total_non_exported if self.all_activities else 0)
        
        if total == 0:
            console.print("[yellow]⚠ No components found[/]")
            return
            
        console.print(Rule(style="bright_cyan"))
        
        component_exploits = {}
        for exploit in results.get('exploits', []):
            comp = exploit['component']
            if comp not in component_exploits:
                component_exploits[comp] = []
            component_exploits[comp].append(exploit)
            
        table = Table(show_header=True, header_style="bold bright_cyan", box=None)
        table.add_column("Component", style="yellow", no_wrap=True)
        table.add_column("Type", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Exploits", style="white")
        
        type_names = {
            'activities': 'activity',
            'services': 'service', 
            'receivers': 'receiver',
            'providers': 'provider'
        }
        
        for comp_type, components in results['components'].items():
            for comp in components:
                name = comp['name']
                short_name = name.split('.')[-1]
                exploit_count = len(component_exploits.get(name, []))
                status = "[green]exported[/]" if comp.get('is_exported', False) else "[red]non-exported[/]"
                
                table.add_row(
                    short_name,
                    type_names.get(comp_type, comp_type),
                    status,
                    str(exploit_count)
                )
                
        console.print(table)
        
        console.print(Rule(style="bright_cyan"))
        console.print(Text("ADB Commands:", style="bold bright_cyan"))
        
        # Get terminal width
        try:
            terminal_width = os.get_terminal_size().columns
        except:
            terminal_width = 80
            
        # Use 90% of terminal width for commands
        max_command_width = int(terminal_width * 0.9)
        
        for comp_name, exploits in component_exploits.items():
            short_name = comp_name.split('.')[-1]
            is_exported = False
            for comp_type in results['components'].values():
                for comp in comp_type:
                    if comp['name'] == comp_name:
                        is_exported = comp.get('is_exported', False)
                        break
                        
            status_tag = "[green](exported)[/]" if is_exported else "[red](non-exported)[/]"
            console.print(f"\n[yellow]{short_name}[/] {status_tag}")
            
            for exploit in exploits:
                if exploit['description']:
                    console.print(f"  [dim]# {exploit['description']}[/dim]")
                
                # Format command with proper line continuation
                formatted_command = self._format_adb_command(exploit['command'], max_command_width)
                console.print(f"  {formatted_command}")

    def save_results(self, results: Dict[str, Any], output_path: str):
        class CustomJSONEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, set):
                    return list(obj)
                if isinstance(obj, IntentExtra):
                    return obj.to_dict()
                return super().default(obj)
                
        Path(output_path).write_text(json.dumps(results, indent=2, cls=CustomJSONEncoder))
        if not self.quiet:
            console.print(f"\n[green]✓ Results saved to:[/] {output_path}")

    def cleanup_dir(self):
        if self.cleanup and self.success and self.decompiled_dir and self.decompiled_dir.exists():
            shutil.rmtree(self.decompiled_dir)
            if not self.quiet:
                console.print("[green]✓ Cleaned up temporary files[/]")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='APK Components Inspector v1.0 - Android Components Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s app.apk                    # Basic analysis (exported only)
  %(prog)s app.apk -a                 # Include non-exported activities
  %(prog)s app.apk -o report.json     # Save results to JSON
  %(prog)s app.apk -v                 # Verbose mode
  %(prog)s app.apk -q                 # Quiet mode (no progress, only results)
  %(prog)s app.apk -c                 # Clean up after analysis

Output includes:
  • Exported components (activities, services, receivers, providers)
  • Non-exported activities (when using -a flag)
  • Intent filters and data schemes
  • Extracted intent extras from Smali analysis
  • Generated ADB exploitation commands
  • Root-based exploits for non-exported activities
        """
    )
    
    parser.add_argument('apk_path', nargs='?', help='Path to APK file')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress progress messages (still shows results)')
    parser.add_argument('-c', '--cleanup', action='store_true', help='Remove decompiled files after analysis')
    parser.add_argument('-a', '--all', action='store_true', help='Include non-exported activities in analysis')
    
    args = parser.parse_args()
    
    if not args.apk_path:
        console.print("╭──────────────── APK Components Inspector ────────────────╮")
        console.print("│ APK Components Inspector                                 │")
        console.print(f"│ [dim]v{VERSION} by {AUTHOR}[/dim]                       │")
        console.print("│                                                          │")
        console.print("│ Usage: python3 apk-components-inspector.py <apk_file>    │")
        console.print("│ Options:                                                 │")
        console.print("│   -o, --output    Save results to JSON file              │")
        console.print("│   -v, --verbose   Enable verbose output                  │")
        console.print("│   -q, --quiet     Suppress progress messages only        │")
        console.print("│   -c, --cleanup   Remove decompiled files after analysis │")
        console.print("│   -a, --all       Include non-exported activities        │")
        console.print("╰──────────────────────────────────────────────────────────╯")
        sys.exit(0)
    
    if not Path(args.apk_path).exists():
        console.print(f"[bold red]Error:[/] APK file not found: {args.apk_path}", style="red")
        sys.exit(1)
        
    analyzer = APKAnalyzer(
        args.apk_path,
        verbose=args.verbose,
        quiet=args.quiet,
        cleanup=args.cleanup,
        all_activities=args.all
    )
    
    results = analyzer.analyze()
    
    if 'error' in results:
        console.print(f"[bold red]Analysis failed:[/] {results['error']}", style="red")
        sys.exit(1)
        
    if args.output:
        analyzer.save_results(results, args.output)
        
    # Always print results (ADB commands) unless there's an error
    # The quiet flag only suppresses progress messages, not the actual output
    analyzer.print_results(results)
        
    analyzer.cleanup_dir()

if __name__ == '__main__':
    main()
