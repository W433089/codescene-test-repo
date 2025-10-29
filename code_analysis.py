#!/usr/bin/env python3
"""
Architecture Component Analyzer

This tool analyzes code repositories line by line to identify architecture components,
their purposes, and ingress/egress data points for creating architecture diagrams.
Outputs detailed analysis to a text file for further processing.

Author: GitHub Copilot
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter

@dataclass
class ArchitectureComponent:
    """Represents an architecture component with its purpose"""
    name: str
    type: str  # service, api, database, queue, cache, frontend, backend, etc.
    purpose: str  # What this component does
    file_path: str
    language: str
    interfaces: List[str]  # APIs, endpoints exposed
    dependencies: List[str]  # What it depends on
    
@dataclass
class DataPoint:
    """Represents ingress or egress data points"""
    name: str
    type: str  # ingress, egress
    protocol: str  # HTTP, HTTPS, TCP, UDP, etc.
    endpoint: str  # URL, port, address
    data_format: str  # JSON, XML, CSV, etc.
    component: str  # Which component this belongs to
    file_path: str
    line_number: int

@dataclass
class Interface:
    """Represents an interface between components"""
    name: str
    source_component: str
    target_component: str
    interface_type: str  # REST_API, SOAP, DATABASE, QUEUE, FILE, etc.
    endpoint: str
    method: str  # GET, POST, etc. for APIs
    data_format: str

@dataclass
class ArchitectureData:
    """Contains architecture analysis data"""
    components: List[ArchitectureComponent]
    data_points: List[DataPoint]
    interfaces: List[Interface]
    languages: Set[str]
    metrics: Dict[str, int]

class CodeAnalyzer:
    """Main analyzer class for identifying architecture components"""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.architecture_data = ArchitectureData(
            components=[],
            data_points=[],
            interfaces=[],
            languages=set(),
            metrics={}
        )
        
        # File extensions to language mapping - expanded for diverse codebases
        self.language_map = {
            '.py': 'Python', '.java': 'Java', '.go': 'Go', '.cs': 'C#', '.vb': 'VB.NET',
            '.js': 'JavaScript', '.ts': 'TypeScript', '.jsx': 'React', '.tsx': 'TypeScript React',
            '.cpp': 'C++', '.c': 'C', '.h': 'C/C++', '.hpp': 'C++', '.cc': 'C++',
            '.php': 'PHP', '.rb': 'Ruby', '.rs': 'Rust', '.kt': 'Kotlin', '.scala': 'Scala',
            '.swift': 'Swift', '.sql': 'SQL', '.pl': 'Perl', '.sh': 'Shell', '.bash': 'Bash',
            '.ps1': 'PowerShell', '.r': 'R', '.m': 'MATLAB', '.dart': 'Dart', '.lua': 'Lua',
            '.xml': 'XML', '.json': 'JSON', '.config': 'Config', '.properties': 'Properties',
            '.yml': 'YAML', '.yaml': 'YAML', '.toml': 'TOML', '.ini': 'INI',
            '.dockerfile': 'Docker', '.tf': 'Terraform', '.hcl': 'HCL',
            '.proto': 'Protocol Buffers', '.thrift': 'Thrift', '.avro': 'Avro',
            '.graphql': 'GraphQL', '.gql': 'GraphQL'
        }
        
        # Component type patterns
        self.component_patterns = {
            # Web/API Components
            'controller': ('API Controller', 'Handles HTTP requests and responses'),
            'api': ('API Service', 'Provides programmatic interface'),
            'service': ('Business Service', 'Business logic and operations'),
            'handler': ('Request Handler', 'Processes specific requests or events'),
            'endpoint': ('API Endpoint', 'Network communication point'),
            
            # Data Components
            'repository': ('Data Repository', 'Data persistence and retrieval'),
            'dao': ('Data Access Object', 'Data access layer'),
            'model': ('Data Model', 'Data structure and validation'),
            'entity': ('Data Entity', 'Database entity representation'),
            'database': ('Database', 'Data storage system'),
            'cache': ('Cache Layer', 'Data caching and optimization'),
            
            # Frontend Components
            'component': ('UI Component', 'User interface element'),
            'view': ('View Layer', 'User interface presentation'),
            'page': ('Web Page', 'Complete web page or screen'),
            'widget': ('UI Widget', 'Reusable UI control'),
            
            # Infrastructure Components
            'queue': ('Message Queue', 'Asynchronous message processing'),
            'worker': ('Background Worker', 'Background task processing'),
            'scheduler': ('Task Scheduler', 'Task scheduling and automation'),
            'gateway': ('API Gateway', 'External system interface'),
            'proxy': ('Proxy Service', 'Request forwarding and routing'),
            
            # Utility Components
            'util': ('Utility Service', 'Helper functions and utilities'),
            'helper': ('Helper Service', 'Support and utility functions'),
            'config': ('Configuration', 'System configuration management'),
            'middleware': ('Middleware', 'Request/response processing'),
        }
        
        # Ingress data point patterns (data coming into the system)
        self.ingress_patterns = {
            # HTTP/REST Ingress
            r'@RequestMapping|@GetMapping|@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping': ('HTTP', 'Spring REST API'),
            r'@RestController|@Controller': ('HTTP', 'Spring Web Controller'),
            r'app\.get|app\.post|app\.put|app\.delete|app\.patch': ('HTTP', 'Express.js Route'),
            r'router\.get|router\.post|router\.put|router\.delete|router\.patch': ('HTTP', 'Router Endpoint'),
            r'@app\.route|@blueprint\.route': ('HTTP', 'Flask Route'),
            r'func.*http\.ResponseWriter.*http\.Request': ('HTTP', 'Go HTTP Handler'),
            r'@WebMvcTest|@RestControllerTest': ('HTTP', 'Spring Test Controller'),
            r'@Path|@GET|@POST|@PUT|@DELETE': ('HTTP', 'JAX-RS REST API'),
            
            # GraphQL Ingress
            r'@Query|@Mutation|@Subscription': ('GRAPHQL', 'GraphQL Resolver'),
            r'type Query|type Mutation|type Subscription': ('GRAPHQL', 'GraphQL Schema'),
            
            # WebSocket Ingress
            r'@OnMessage|@OnOpen|@OnClose': ('WEBSOCKET', 'WebSocket Handler'),
            r'socket\.on|ws\.on': ('WEBSOCKET', 'WebSocket Event Handler'),
            
            # Message Queue Ingress
            r'@RabbitListener|@KafkaListener|@JmsListener|@EventListener': ('MESSAGE', 'Message Consumer'),
            r'@SqsListener|@ServiceActivator': ('MESSAGE', 'Message Queue Consumer'),
            r'subscribe|on_message|consume': ('MESSAGE', 'Event Subscriber'),
            
            # Database Events
            r'@EventHandler|@Entity|@Repository': ('DATA', 'Database Event Handler'),
            r'@Transactional|@Query': ('DATA', 'Database Operation'),
            
            # File System
            r'FileWatcher|WatchService|@FileSystemWatcher': ('FILE', 'File System Monitor'),
            
            # gRPC Ingress
            r'rpc\s+\w+|service\s+\w+.*\{': ('GRPC', 'gRPC Service Definition'),
            r'@GrpcService': ('GRPC', 'gRPC Service Implementation'),
            
            # Scheduled Tasks
            r'@Scheduled|@Cron|cron\.schedule': ('SCHEDULED', 'Scheduled Task'),
            
            # CLI/Command Line
            r'if\s+__name__\s*==\s*[\'"]__main__[\'"]|main\(\)|public\s+static\s+void\s+main': ('CLI', 'Command Line Entry Point'),
        }
        
        # Egress data point patterns (data going out of the system)
        self.egress_patterns = {
            # HTTP Egress
            r'HttpClient|RestTemplate|WebClient': ('HTTP', 'HTTP Client Call'),
            r'requests\.get|requests\.post|fetch\(': ('HTTP', 'HTTP Request'),
            r'axios\.|http\.get|http\.post': ('HTTP', 'HTTP Library Call'),
            
            # Database Egress
            r'SqlConnection|JdbcTemplate|EntityManager': ('DATABASE', 'Database Connection'),
            r'MongoClient|RedisClient': ('DATABASE', 'NoSQL Database Client'),
            
            # Message Queue Egress
            r'RabbitTemplate|KafkaTemplate|JmsTemplate': ('MESSAGE', 'Message Producer'),
            r'publish|send_message': ('MESSAGE', 'Message Publisher'),
            
            # File System
            r'FileWriter|FileOutputStream|open\(.*[\'"]w': ('FILE', 'File Writer'),
        }
        
        # Interface patterns
        self.interface_patterns = {
            r'/api/[^"\s]+': 'REST_API',
            r'/v\d+/[^"\s]+': 'REST_API',
            r'/graphql': 'GRAPHQL',
            r'/ws/|/websocket': 'WEBSOCKET',
            r'jdbc:|mongodb:|redis:': 'DATABASE',
            r'amqp:|kafka:': 'MESSAGE_QUEUE',
        }
    
    def analyze_repository(self) -> ArchitectureData:
        """Main method to analyze the entire repository"""
        print(f"🏗️  Analyzing repository: {self.repo_path}")
        
        # 1. Scan all files
        all_files = self._scan_files()
        
        # 2. Analyze each file to identify components and data points
        print(f"  📝 Analyzing {len(all_files)} files for architecture components...")
        for i, file_path in enumerate(all_files):
            if i % 500 == 0 and i > 0:
                print(f"    Processed {i}/{len(all_files)} files...")
            self._analyze_file(file_path)
        
        # 3. Identify interfaces between components
        self._identify_interfaces()
        
        # 4. Calculate metrics
        self._calculate_metrics()
        
        # For debugging: print the architecture data summary
        self._debug_print_architecture_data()
        
        return self.architecture_data
    
    def _scan_files(self) -> List[Path]:
        """Scan repository for code files"""
        print("  🔍 Scanning for code files...")
        code_files = []
        ignore_dirs = {'.git', '__pycache__', 'node_modules', 'target', 'bin', 'obj', '.vs', '.vscode'}
        
        total_dirs = 0
        for root, dirs, files in os.walk(self.repo_path):
            total_dirs += 1
            if total_dirs % 100 == 0:
                print(f"    Scanned {total_dirs} directories...")
            
            # Remove ignored directories
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix.lower() in self.language_map:
                    code_files.append(file_path)
        
        print(f"  ✅ Found {len(code_files)} code files")
        return code_files
    
    def _analyze_file(self, file_path: Path):
        """Analyze a single file to identify architecture components and data points"""
        try:
            extension = file_path.suffix.lower()
            language = self.language_map.get(extension, 'Unknown')
            self.architecture_data.languages.add(language)
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Identify architecture components based on file name and content
            self._identify_architecture_components(file_path, content, language)
            
            # Identify ingress and egress data points
            self._identify_data_points(file_path, content, language)
                
        except Exception as e:
            pass  # Skip files that can't be read
    
    def _identify_architecture_components(self, file_path: Path, content: str, language: str):
        """Identify architecture components based on actual file analysis - no assumptions"""
        file_name = file_path.stem.lower()
        file_dir = file_path.parent.name.lower()
        
        # Only classify if there's clear evidence, otherwise mark as unclassified
        component_type = 'Unclassified'
        purpose = 'File purpose not determined from analysis'
        
        # Only assign type if pattern is found in filename or directory
        for pattern, (comp_type, comp_purpose) in self.component_patterns.items():
            if pattern in file_name or pattern in file_dir:
                component_type = comp_type
                purpose = f"Classified as {comp_type.lower()} based on file/directory naming pattern"
                break
        
        # Extract only actual interfaces found in content
        interfaces = self._extract_interfaces(content)
        
        # Extract only actual dependencies found in code
        dependencies = self._extract_dependencies(content, language)
        
        # Create component with factual data only
        component = ArchitectureComponent(
            name=file_path.stem,
            type=component_type,
            purpose=purpose,
            file_path=str(file_path.relative_to(self.repo_path)),
            language=language,
            interfaces=interfaces if interfaces else [],
            dependencies=dependencies if dependencies else []
        )
        
        self.architecture_data.components.append(component)
    
    def _identify_data_points(self, file_path: Path, content: str, language: str):
        """Identify ingress and egress data points"""
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for ingress patterns
            for pattern, (protocol, description) in self.ingress_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    endpoint = self._extract_endpoint_from_line(line)
                    data_format = self._extract_data_format_from_line(line)
                    
                    data_point = DataPoint(
                        name=f"Ingress_{file_path.stem}_{line_num}",
                        type='ingress',
                        protocol=protocol,
                        endpoint=endpoint,
                        data_format=data_format,
                        component=file_path.stem,
                        file_path=str(file_path.relative_to(self.repo_path)),
                        line_number=line_num
                    )
                    self.architecture_data.data_points.append(data_point)
            
            # Check for egress patterns
            for pattern, (protocol, description) in self.egress_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    endpoint = self._extract_endpoint_from_line(line)
                    data_format = self._extract_data_format_from_line(line)
                    
                    data_point = DataPoint(
                        name=f"Egress_{file_path.stem}_{line_num}",
                        type='egress',
                        protocol=protocol,
                        endpoint=endpoint,
                        data_format=data_format,
                        component=file_path.stem,
                        file_path=str(file_path.relative_to(self.repo_path)),
                        line_number=line_num
                    )
                    self.architecture_data.data_points.append(data_point)
    
    def _extract_interfaces(self, content: str) -> List[str]:
        """Extract API endpoints and interfaces from content"""
        interfaces = []
        
        for pattern, interface_type in self.interface_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                interfaces.append(f"{interface_type}: {match}")
        
        return interfaces[:5]  # Limit to 5 interfaces per component
    
    def _extract_dependencies(self, content: str, language: str) -> List[str]:
        """Extract dependencies based on language"""
        dependencies = []
        
        if language == 'Python':
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('import ') or line.startswith('from '):
                    dep = line.split()[1] if len(line.split()) > 1 else ''
                    if dep and not dep.startswith('.'):  # Skip relative imports
                        dependencies.append(dep.split('.')[0])  # Get top-level package
        
        elif language == 'Java':
            import_pattern = r'import\s+([^;]+);'
            imports = re.findall(import_pattern, content)
            for imp in imports:
                if not imp.startswith('java.') and '.' in imp:  # Skip standard library
                    dependencies.append(imp.split('.')[0])
        
        elif language in ['JavaScript', 'TypeScript']:
            import_pattern = r'import\s+.*?from\s+[\'"]([^\'"]+)[\'"]'
            require_pattern = r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)'
            imports = re.findall(import_pattern, content) + re.findall(require_pattern, content)
            for imp in imports:
                if not imp.startswith('.') and not imp.startswith('/'):  # Skip relative imports
                    dependencies.append(imp.split('/')[0])
        
        elif language == 'C#':
            using_pattern = r'using\s+([^;]+);'
            usings = re.findall(using_pattern, content)
            for using in usings:
                if '.' in using and not using.startswith('System'):  # Skip system namespaces
                    dependencies.append(using.split('.')[0])
        
        elif language == 'Go':
            import_pattern = r'import\s+(?:\(\s*([^)]+)\s*\)|"([^"]+)")'
            imports = re.findall(import_pattern, content)
            for group in imports:
                for imp in group:
                    if imp and '/' in imp:  # External packages usually have /
                        dependencies.append(imp.split('/')[0])
        
        # Remove duplicates and limit
        return list(set(dependencies))[:10]
    
    def _extract_endpoint_from_line(self, line: str) -> str:
        """Extract URL/endpoint from a line of code"""
        url_patterns = [
            r'"(https?://[^"]+)"',
            r"'(https?://[^']+)'",
            r'"(/[^"]*)"',
            r"'(/[^']*)'",
            r'@"([^"]+)"',  # C# verbatim strings
        ]
        
        for pattern in url_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        
        return 'Dynamic endpoint'
    
    def _extract_data_format_from_line(self, line: str) -> str:
        """Extract data format from a line of code"""
        line_lower = line.lower()
        
        if 'json' in line_lower:
            return 'JSON'
        elif 'xml' in line_lower:
            return 'XML'
        elif 'csv' in line_lower:
            return 'CSV'
        elif 'yaml' in line_lower or 'yml' in line_lower:
            return 'YAML'
        elif 'protobuf' in line_lower or 'proto' in line_lower:
            return 'Protobuf'
        else:
            return 'Unknown'
    
    def _identify_interfaces(self):
        """Identify interfaces between components based on data points"""
        print("  🔗 Identifying component interfaces...")
        
        # Group data points by component
        component_data_points = defaultdict(list)
        for data_point in self.architecture_data.data_points:
            component_data_points[data_point.component].append(data_point)
        
        # Create interfaces between components with matching egress/ingress points
        for source_comp, source_points in component_data_points.items():
            egress_points = [dp for dp in source_points if dp.type == 'egress']
            
            for egress_point in egress_points:
                # Find potential target components with matching ingress points
                for target_comp, target_points in component_data_points.items():
                    if source_comp != target_comp:
                        ingress_points = [dp for dp in target_points if dp.type == 'ingress']
                        
                        for ingress_point in ingress_points:
                            if self._points_match(egress_point, ingress_point):
                                interface = Interface(
                                    name=f"{source_comp} → {target_comp}",
                                    source_component=source_comp,
                                    target_component=target_comp,
                                    interface_type=egress_point.protocol,
                                    endpoint=egress_point.endpoint,
                                    method='Unknown',
                                    data_format=egress_point.data_format
                                )
                                self.architecture_data.interfaces.append(interface)
        
        print(f"    ✅ Found {len(self.architecture_data.interfaces)} potential interfaces")
    
    def _points_match(self, egress_point: DataPoint, ingress_point: DataPoint) -> bool:
        """Check if egress and ingress points could be connected"""
        return (egress_point.protocol == ingress_point.protocol and 
                egress_point.data_format == ingress_point.data_format)
    
    def _calculate_metrics(self):
        """Calculate repository metrics"""
        component_types = Counter(c.type for c in self.architecture_data.components)
        
        self.architecture_data.metrics = {
            'total_components': len(self.architecture_data.components),
            'total_languages': len(self.architecture_data.languages),
            'total_data_points': len(self.architecture_data.data_points),
            'ingress_points': len([dp for dp in self.architecture_data.data_points if dp.type == 'ingress']),
            'egress_points': len([dp for dp in self.architecture_data.data_points if dp.type == 'egress']),
            'total_interfaces': len(self.architecture_data.interfaces),
            'component_types': dict(component_types)
        }

    def _debug_print_architecture_data(self):
        """Debugging: print the architecture data summary"""
        print("\n--- Architecture Data Summary ---")
        print(f"Total Components: {len(self.architecture_data.components)}")
        print(f"Total Data Points: {len(self.architecture_data.data_points)}")
        print(f"Total Interfaces: {len(self.architecture_data.interfaces)}")
        print(f"Languages: {', '.join(self.architecture_data.languages)}")
        
        # Print component details
        for component in self.architecture_data.components[:5]:  # Limit to first 5 components
            print(f"- {component.name} ({component.type}): {component.purpose}")
        
        # Print data point details
        for data_point in self.architecture_data.data_points[:5]:  # Limit to first 5 data points
            print(f"- {data_point.name} ({data_point.type}): {data_point.endpoint}")
        
        # Print interface details
        for interface in self.architecture_data.interfaces[:5]:  # Limit to first 5 interfaces
            print(f"- {interface.name}: {interface.source_component} → {interface.target_component}")
        print("----------------------------------")

class TextOutputGenerator:
    """Generates detailed text output for architecture analysis"""
    
    def __init__(self, architecture_data: ArchitectureData, repo_name: str):
        self.data = architecture_data
        self.repo_name = repo_name
    
    def generate_text_report(self, output_path: str):
        """Generate comprehensive text report"""
        report_content = self._generate_text_content()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"📄 Architecture analysis saved to: {output_path}")
    
    def _generate_text_content(self) -> str:
        """Generate concise architectural facts for diagram generation"""
        content = []
        
        # Header
        content.append(f"ARCHITECTURE ANALYSIS - {self.repo_name}")
        content.append("=" * 60)
        content.append("")
        
        # Component Summary
        component_types = Counter(c.type for c in self.data.components if c.type != 'Unclassified')
        if component_types:
            content.append("COMPONENTS BY TYPE:")
            for comp_type, count in sorted(component_types.items(), key=lambda x: x[1], reverse=True):
                components_of_type = [c.name for c in self.data.components if c.type == comp_type]
                content.append(f"{comp_type}: {', '.join(components_of_type)}")
            content.append("")
        
        # Key Interfaces
        key_interfaces = []
        for component in self.data.components:
            if component.interfaces:
                for interface in component.interfaces[:2]:  # Limit to 2 per component
                    key_interfaces.append(f"{component.name}: {interface}")
        
        if key_interfaces:
            content.append("KEY INTERFACES:")
            for interface in key_interfaces[:10]:  # Limit total
                content.append(f"  {interface}")
            content.append("")
        
        # Component Connections
        if self.data.interfaces:
            content.append("COMPONENT CONNECTIONS:")
            for interface in self.data.interfaces[:15]:  # Limit connections
                content.append(f"{interface.source_component} -> {interface.target_component} ({interface.interface_type})")
            content.append("")
        
        # Data Flow Points (simplified)
        if self.data.data_points:
            ingress_count = len([dp for dp in self.data.data_points if dp.type == 'ingress'])
            egress_count = len([dp for dp in self.data.data_points if dp.type == 'egress'])
            protocols = sorted(set(dp.protocol for dp in self.data.data_points))
            
            content.append("DATA FLOW SUMMARY:")
            content.append(f"Entry points: {ingress_count}")
            content.append(f"Exit points: {egress_count}")
            content.append(f"Protocols: {', '.join(protocols)}")
            content.append("")
        
        # Diagram Layout
        unique_types = [t for t in set(c.type for c in self.data.components) if t != 'Unclassified']
        if unique_types:
            layer_priority = {
                'UI Component': 1, 'View Layer': 1, 'Web Page': 1,
                'API Controller': 2, 'API Service': 2, 'API Endpoint': 2,
                'Business Service': 3, 'Request Handler': 3, 'Middleware': 3,
                'Data Repository': 4, 'Data Access Object': 4, 'Database': 4,
                'Cache Layer': 5, 'Message Queue': 5, 'Background Worker': 5
            }
            
            sorted_types = sorted(unique_types, key=lambda x: (layer_priority.get(x, 99), x))
            
            content.append("SUGGESTED DIAGRAM LAYERS:")
            for i, comp_type in enumerate(sorted_types, 1):
                components = [c.name for c in self.data.components if c.type == comp_type]
                content.append(f"Layer {i} ({comp_type}): {', '.join(components)}")
            content.append("")
        
        content.append("=" * 60)
        
        return "\n".join(content)

def main():
    """Main entry point"""
    print("🏗️  Architecture Component Analyzer")
    print("=" * 50)
    
    # Prompt for input folder
    repo_path = input("📂 Enter the path to your repository/folder: ").strip()
    
    # Remove quotes if user copied path with quotes
    if repo_path.startswith('"') and repo_path.endswith('"'):
        repo_path = repo_path[1:-1]
    elif repo_path.startswith("'") and repo_path.endswith("'"):
        repo_path = repo_path[1:-1]
    
    if not repo_path or not os.path.exists(repo_path):
        print(f"❌ Error: Repository path '{repo_path}' does not exist.")
        return 1
    
    # Prompt for output file
    output_file = input("📄 Enter output text file name (default: architecture_analysis.txt): ").strip()
    if not output_file:
        output_file = "architecture_analysis.txt"
    
    # Ensure .txt extension
    if not output_file.endswith('.txt'):
        output_file += '.txt'
    
    try:
        # Analyze repository
        analyzer = CodeAnalyzer(repo_path)
        architecture_data = analyzer.analyze_repository()
        
        print(f"\n✅ Analysis complete!")
        print(f"   📦 {len(architecture_data.components)} architecture components")
        print(f"   🔄 {len(architecture_data.data_points)} data flow points")
        print(f"   🔗 {len(architecture_data.interfaces)} component interfaces")
        print(f"   💻 {len(architecture_data.languages)} programming languages")
        
        # Generate text report
        repo_name = os.path.basename(os.path.abspath(repo_path))
        generator = TextOutputGenerator(architecture_data, repo_name)
        generator.generate_text_report(output_file)
        
        print(f"\n🎉 Architecture analysis saved to: {output_file}")
        print("   Use this text file for further analysis or diagram generation!")
        
    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user.")
        return 1
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())