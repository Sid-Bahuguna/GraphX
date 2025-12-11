#!/usr/bin/env python3
"""
SMART GraphQL Vulnerability Scanner - Complete Edition
A comprehensive security testing tool for GraphQL APIs
Developed by Sidharth Bahuguna
"""

import requests
import json
import argparse
import sys
from typing import Dict, List, Optional
from urllib.parse import urljoin
import time
from datetime import datetime
import re


VERSION = "v2.0"


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class GraphQLScanner:
    """Main scanner class for GraphQL vulnerability detection"""
    
    def __init__(self, target_url: str, headers: Optional[Dict] = None, timeout: int = 10, method: str = 'POST'):
        self.target_url = target_url.rstrip('/')
        self.base_url = '/'.join(self.target_url.split('/')[:3])
        self.timeout = timeout
        self.method = method.upper()
        self.headers = headers or {}
        self.headers.setdefault('Content-Type', 'application/json')
        self.schema = None
        self.vulnerabilities = []
        self.queries = []
        self.mutations = []
        self.subscriptions = []
        self.types = []
        self.directives = []
        self.supported_methods = []
        self.graphql_endpoints = []
        self.false_positive_threshold = 0.7
    
    def print_banner(self):
        """Print the tool banner with ASCII art"""
        banner = f"""{Colors.RED}
   ██████╗ ██████╗  ██████╗ ██╗    ██╗
  ██╔════╝ ██╔══██╗██╔═══██╗██║    ██║
  ███████╗ ██████╔╝██║   ██║██║ █╗ ██║
  ╚════██║ ██╔══██╗██║   ██║██║███╗██║
  ███████║ ██████╔╝╚██████╔╝╚███╔███╔╝
  ╚══════╝ ╚═════╝  ╚═════╝  ╚══╝╚══╝{Colors.ENDC}
"""
        print(banner)
        print(f"\t\t\t{Colors.GREEN}GraphX {VERSION}{Colors.ENDC}")
        print(f"\t\t\t{Colors.GREEN}Developed by Sidharth Bahuguna{Colors.ENDC}")
        print()
        print(f"{Colors.YELLOW}Target: {self.target_url}{Colors.ENDC}")
        print(f"{Colors.YELLOW}Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
        print(f"{Colors.YELLOW}HTTP Method: {self.method}{Colors.ENDC}\n")
    
    def _add_vulnerability(self, vuln_type: str, severity: str, description: str, 
                          impact: str, recommendation: str, proof: Optional[Dict] = None,
                          confidence: float = 1.0):
        """Add vulnerability with proof of concept"""
        if confidence < self.false_positive_threshold:
            return
        
        vuln = {
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'impact': impact,
            'recommendation': recommendation,
            'confidence': f"{int(confidence * 100)}%"
        }
        
        if proof:
            vuln['proof_of_concept'] = proof
        
        self.vulnerabilities.append(vuln)
    
    def send_query(self, query: str, variables: Optional[Dict] = None, method: Optional[str] = None, endpoint: Optional[str] = None) -> Optional[Dict]:
        """Send GraphQL query and return response"""
        method = method or self.method
        endpoint = endpoint or self.target_url
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        
        try:
            if method == 'POST':
                response = requests.post(endpoint, json=payload, headers=self.headers, timeout=self.timeout, verify=True, allow_redirects=True)
            elif method == 'GET':
                response = requests.get(endpoint, params={'query': query, 'variables': json.dumps(variables) if variables else None}, headers=self.headers, timeout=self.timeout, verify=True, allow_redirects=True)
            elif method in ['PUT', 'PATCH']:
                response = requests.request(method, endpoint, json=payload, headers=self.headers, timeout=self.timeout, verify=True)
            else:
                return None
            
            return {
                'status_code': response.status_code,
                'data': response.json() if response.text and 'json' in response.headers.get('content-type', '') else {},
                'headers': dict(response.headers),
                'text': response.text
            }
        except:
            return None
    
    def test_endpoint_detection(self):
        """Test common GraphQL endpoint paths"""
        print(f"\n{Colors.BLUE}[*] Testing Endpoint Detection...{Colors.ENDC}")
        common_paths = ['/graphql', '/api/graphql', '/graphiql', '/playground', '/v1/graphql', '/gql']
        
        for path in common_paths:
            test_url = urljoin(self.base_url, path)
            try:
                response = self.send_query('{ __typename }', endpoint=test_url)
                if response and response['status_code'] in [200, 400]:
                    if '__typename' in str(response) or 'errors' in str(response):
                        self.graphql_endpoints.append(test_url)
                        print(f"{Colors.GREEN}[✓] Found: {test_url}{Colors.ENDC}")
            except:
                pass
    
    def test_graphiql_playground(self):
        """Check for GraphiQL or Playground exposure"""
        print(f"\n{Colors.BLUE}[*] Testing GraphiQL/Playground Exposure...{Colors.ENDC}")
        try:
            response = requests.get(self.target_url, headers={'Accept': 'text/html'}, timeout=self.timeout)
            html = response.text.lower()
            exposed = []
            if 'graphiql' in html: exposed.append('GraphiQL')
            if 'playground' in html: exposed.append('Playground')
            if 'altair' in html: exposed.append('Altair')
            
            if exposed:
                print(f"{Colors.RED}[!] Console exposed: {', '.join(exposed)}{Colors.ENDC}")
                self._add_vulnerability('Interactive Console Exposed', 'HIGH', f'Console: {", ".join(exposed)}', 
                    'Interactive API exploration', 'Disable in production',
                    {'consoles': exposed, 'manual_test': f'Open {self.target_url} in browser'}, 1.0)
        except:
            pass
    
    def test_http_methods(self):
        """Test HTTP methods"""
        print(f"\n{Colors.BLUE}[*] Testing HTTP Methods...{Colors.ENDC}")
        for method in ['POST', 'GET', 'PUT', 'PATCH']:
            try:
                response = self.send_query("{ __typename }", method=method)
                if response and response['status_code'] in [200, 201]:
                    self.supported_methods.append(method)
                    print(f"{Colors.GREEN}[✓] {method} supported{Colors.ENDC}")
            except:
                pass
        
        if 'GET' in self.supported_methods:
            self._add_vulnerability('GET Method Enabled', 'MEDIUM', 'GET requests accepted', 
                'CSRF attacks possible', 'Use POST only',
                {'manual_test': f'curl -X GET "{self.target_url}?query={{__typename}}"'}, 1.0)
    
    def test_introspection(self) -> bool:
        """Test introspection"""
        print(f"\n{Colors.BLUE}[*] Testing Introspection...{Colors.ENDC}")
        query = "query { __schema { types { kind name fields { name args { name } } inputFields { name } } queryType { name } mutationType { name } subscriptionType { name } } }"
        response = self.send_query(query)
        
        if response and response['status_code'] == 200:
            data = response.get('data', {})
            if '__schema' in data or (isinstance(data, dict) and 'data' in data and '__schema' in data.get('data', {})):
                self.schema = data.get('data', {}).get('__schema') or data.get('__schema')
                print(f"{Colors.RED}[!] CRITICAL: Introspection ENABLED{Colors.ENDC}")
                self._add_vulnerability('Introspection Enabled', 'CRITICAL', 'Schema publicly accessible',
                    'Complete API exposure', 'Disable in production',
                    {'query': '{ __schema { types { name } } }', 'manual_test': f'curl -X POST {self.target_url} -H "Content-Type: application/json" -d \'{{"query":"{{ __schema {{ types {{ name }} }} }}"}}\''}, 1.0)
                self._parse_schema()
                return True
            else:
                print(f"{Colors.GREEN}[✓] Introspection disabled{Colors.ENDC}")
        return False
    
    def _parse_schema(self):
        """Parse schema"""
        if not self.schema:
            return
        self.types = self.schema.get('types', [])
        query_type = self.schema.get('queryType', {}).get('name')
        mutation_type = self.schema.get('mutationType', {}).get('name')
        subscription_type = self.schema.get('subscriptionType', {}).get('name')
        
        for t in self.types:
            if t.get('name') == query_type:
                self.queries = t.get('fields', [])
            elif t.get('name') == mutation_type:
                self.mutations = t.get('fields', [])
            elif t.get('name') == subscription_type:
                self.subscriptions = t.get('fields', [])
        
        print(f"{Colors.CYAN}[*] Found: {len(self.queries)} queries, {len(self.mutations)} mutations{Colors.ENDC}")
    
    def test_idor(self):
        """Test IDOR"""
        print(f"\n{Colors.BLUE}[*] Testing IDOR...{Colors.ENDC}")
        if not self.queries:
            return
        
        id_queries = [q for q in self.queries if any(arg.get('name', '').lower() in ['id', 'userid', 'user_id'] for arg in q.get('args', []))]
        
        for query in id_queries[:3]:
            successful = []
            for test_id in [1, 2, 999]:
                test_q = self._generate_query(query.get('name'), query.get('args', []), {'id': test_id})
                resp = self.send_query(test_q)
                if resp and resp['status_code'] == 200:
                    data = resp.get('data', {})
                    if data and not self._has_auth_error(resp):
                        successful.append({'id': test_id, 'query': test_q})
            
            if len(successful) >= 2:
                print(f"{Colors.RED}[!] IDOR in {query.get('name')}{Colors.ENDC}")
                self._add_vulnerability('IDOR', 'HIGH', f'Unauthorized access in {query.get("name")}',
                    'Data access bypass', 'Implement authorization',
                    {'tested_ids': [s['id'] for s in successful], 'example': successful[0]['query']}, 0.9 if len(successful) >= 3 else 0.75)
                break
    
    def test_field_level_authorization(self):
        """Test field-level auth"""
        print(f"\n{Colors.BLUE}[*] Testing Field-Level Authorization...{Colors.ENDC}")
        sensitive = ['isadmin', 'role', 'permissions', 'admin', 'secret', 'private']
        
        for t in self.types:
            for field in t.get('fields', []):
                if any(s in field.get('name', '').lower() for s in sensitive):
                    print(f"{Colors.YELLOW}[!] Sensitive: {t.get('name')}.{field.get('name')}{Colors.ENDC}")
                    self._add_vulnerability('Field-Level Auth Issue', 'HIGH', f'Sensitive field: {field.get("name")}',
                        'Privilege disclosure', 'Apply field-level control',
                        {'type': t.get('name'), 'field': field.get('name')}, 0.8)
    
    def test_missing_auth_mutations(self):
        """Test mutation auth"""
        print(f"\n{Colors.BLUE}[*] Testing Missing Auth on Mutations...{Colors.ENDC}")
        keywords = ['delete', 'remove', 'update', 'create', 'admin']
        
        for mut in self.mutations[:5]:
            if any(k in mut.get('name', '').lower() for k in keywords):
                test_mut = f"mutation {{ {mut.get('name')} {{ __typename }} }}"
                resp = self.send_query(test_mut)
                if resp and resp['status_code'] == 200 and not self._has_auth_error(resp):
                    print(f"{Colors.RED}[!] Unauth mutation: {mut.get('name')}{Colors.ENDC}")
                    self._add_vulnerability('Missing Authentication', 'CRITICAL', f'Mutation "{mut.get("name")}" accessible',
                        'Unauthorized modification', 'Require authentication',
                        {'mutation': mut.get('name'), 'test': test_mut}, 0.95)
    
    def test_sql_injection(self):
        """Test SQL injection"""
        print(f"\n{Colors.BLUE}[*] Testing SQL Injection...{Colors.ENDC}")
        payloads = ["' OR '1'='1", "1' AND 1=1--", "' UNION SELECT NULL--"]
        
        for q in self.queries[:3]:
            for arg in q.get('args', [])[:2]:
                for payload in payloads:
                    test_q = self._generate_query(q.get('name'), q.get('args', []), {arg.get('name'): payload})
                    resp = self.send_query(test_q)
                    if resp and resp['status_code'] == 500:
                        text = json.dumps(resp).lower()
                        if any(e in text for e in ['sql', 'syntax error', 'mysql', 'postgresql']):
                            print(f"{Colors.RED}[!] SQLi in {q.get('name')}.{arg.get('name')}{Colors.ENDC}")
                            self._add_vulnerability('SQL Injection', 'CRITICAL', f'SQLi in {q.get("name")}',
                                'Database compromise', 'Use parameterized queries',
                                {'query': q.get('name'), 'parameter': arg.get('name'), 'payload': payload}, 0.95)
                            return
    
    def test_query_depth_abuse(self):
        """Test depth limits"""
        print(f"\n{Colors.BLUE}[*] Testing Query Depth...{Colors.ENDC}")
        deep = self._generate_deep_query(15)
        resp = self.send_query(deep)
        if resp and resp['status_code'] == 200:
            print(f"{Colors.RED}[!] No depth limit{Colors.ENDC}")
            self._add_vulnerability('Missing Query Depth Limit', 'MEDIUM', 'Deep queries accepted',
                'Resource exhaustion', 'Limit depth to 5-7 levels',
                {'depth_tested': 15}, 1.0)
    
    def test_alias_overloading(self):
        """Test alias DoS"""
        print(f"\n{Colors.BLUE}[*] Testing Alias Overloading...{Colors.ENDC}")
        if not self.queries:
            return
        
        alias_q = "query {\n" + "\n".join([f"  a{i}: {self.queries[0].get('name')}" for i in range(100)]) + "\n}"
        start = time.time()
        resp = self.send_query(alias_q)
        elapsed = time.time() - start
        
        if resp and resp['status_code'] == 200:
            print(f"{Colors.RED}[!] Alias attack possible ({elapsed:.2f}s){Colors.ENDC}")
            self._add_vulnerability('Alias-Based DoS', 'HIGH', 'No alias limit',
                'Resource exhaustion', 'Limit aliases',
                {'aliases_tested': 100, 'time': f'{elapsed:.2f}s'}, 1.0)
    
    def test_mass_assignment(self):
        """Test mass assignment"""
        print(f"\n{Colors.BLUE}[*] Testing Mass Assignment...{Colors.ENDC}")
        dangerous = ['role', 'isadmin', 'admin', 'balance', 'permissions']
        
        for t in self.types:
            if t.get('kind') == 'INPUT_OBJECT':
                for field in t.get('inputFields', []):
                    if field.get('name', '').lower() in dangerous:
                        print(f"{Colors.YELLOW}[!] Risky input: {t.get('name')}.{field.get('name')}{Colors.ENDC}")
                        self._add_vulnerability('Mass Assignment', 'HIGH', f'Privileged field: {field.get("name")}',
                            'Privilege escalation', 'Remove sensitive fields',
                            {'input': t.get('name'), 'field': field.get('name')}, 0.8)
    
    def test_sensitive_fields_exposure(self):
        """Scan sensitive fields"""
        print(f"\n{Colors.BLUE}[*] Scanning Sensitive Fields...{Colors.ENDC}")
        keywords = ['password', 'token', 'apikey', 'jwt', 'secret', 'key']
        
        for t in self.types:
            for field in t.get('fields', []):
                if any(k in field.get('name', '').lower() for k in keywords):
                    print(f"{Colors.RED}[!] Sensitive: {t.get('name')}.{field.get('name')}{Colors.ENDC}")
                    self._add_vulnerability('Sensitive Field Exposure', 'HIGH', f'Sensitive field: {field.get("name")}',
                        'Information disclosure', 'Remove or restrict',
                        {'type': t.get('name'), 'field': field.get('name')}, 0.75)
    
    def test_error_message_leaks(self):
        """Test error leaks"""
        print(f"\n{Colors.BLUE}[*] Testing Error Leaks...{Colors.ENDC}")
        resp = self.send_query("query { invalid { bad } }")
        if resp:
            text = json.dumps(resp).lower()
            leaks = [i for i in ['stack', 'exception', 'line', 'file', 'resolver'] if i in text]
            if leaks:
                print(f"{Colors.YELLOW}[!] Error leaks detected{Colors.ENDC}")
                self._add_vulnerability('Verbose Errors', 'MEDIUM', 'Internal details in errors',
                    'Information disclosure', 'Generic errors only',
                    {'leaked': leaks}, 0.9)
    
    def test_cors_misconfiguration(self):
        """Test CORS"""
        print(f"\n{Colors.BLUE}[*] Testing CORS...{Colors.ENDC}")
        for origin in ['https://evil.com', 'null']:
            hdrs = self.headers.copy()
            hdrs['Origin'] = origin
            try:
                resp = requests.post(self.target_url, json={"query": "{ __typename }"}, headers=hdrs, timeout=self.timeout)
                cors = resp.headers.get('Access-Control-Allow-Origin', '')
                if cors in ['*', origin]:
                    print(f"{Colors.RED}[!] Permissive CORS: {cors}{Colors.ENDC}")
                    self._add_vulnerability('CORS Misconfiguration', 'HIGH', f'CORS allows: {cors}',
                        'Cross-origin attacks', 'Restrict origins',
                        {'allowed': cors, 'manual_test': f'curl -H "Origin: https://evil.com" {self.target_url}'}, 1.0)
                    return
            except:
                pass
    
    def _generate_query(self, name: str, args: List[Dict], params: Dict) -> str:
        """Generate query"""
        arg_strs = []
        for arg in args:
            arg_name = arg.get('name')
            if arg_name in params:
                val = params[arg_name]
                if isinstance(val, str):
                    arg_strs.append(f'{arg_name}: "{val}"')
                else:
                    arg_strs.append(f'{arg_name}: {val}')
        args_str = ', '.join(arg_strs) if arg_strs else ''
        return f"query {{ {name}({args_str}) {{ __typename }} }}"
    
    def _generate_deep_query(self, depth: int) -> str:
        """Generate deep query"""
        q = "query { __schema { types { "
        for _ in range(depth):
            q += "fields { type { "
        q += "name"
        for _ in range(depth):
            q += " } }"
        q += " } } }"
        return q
    
    def _has_auth_error(self, response: Dict) -> bool:
        """Check auth error"""
        text = json.dumps(response).lower()
        return any(k in text for k in ['unauthorized', 'forbidden', 'authentication', 'permission', 'access denied'])
    
    def _has_validation_error(self, response: Dict) -> bool:
        """Check validation error"""
        text = json.dumps(response).lower()
        return any(k in text for k in ['validation', 'invalid', 'error', 'malformed'])
    
    def generate_report(self):
        """Generate report"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}VULNERABILITY REPORT{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.ENDC}\n")
        
        if not self.vulnerabilities:
            print(f"{Colors.GREEN}[✓] No vulnerabilities detected!{Colors.ENDC}")
            return
        
        critical = [v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']
        high = [v for v in self.vulnerabilities if v['severity'] == 'HIGH']
        medium = [v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']
        low = [v for v in self.vulnerabilities if v['severity'] == 'LOW']
        
        print(f"{Colors.RED}CRITICAL: {len(critical)}{Colors.ENDC}")
        print(f"{Colors.YELLOW}HIGH: {len(high)}{Colors.ENDC}")
        print(f"{Colors.YELLOW}MEDIUM: {len(medium)}{Colors.ENDC}")
        print(f"{Colors.CYAN}LOW: {len(low)}{Colors.ENDC}\n")
        
        for idx, vuln in enumerate(self.vulnerabilities, 1):
            color = {'CRITICAL': Colors.RED, 'HIGH': Colors.YELLOW, 'MEDIUM': Colors.YELLOW, 'LOW': Colors.CYAN}.get(vuln['severity'], Colors.ENDC)
            
            print(f"{Colors.BOLD}[{idx}] {vuln['type']}{Colors.ENDC}")
            print(f"    Severity: {color}{vuln['severity']}{Colors.ENDC}")
            print(f"    Confidence: {Colors.GREEN}{vuln.get('confidence', 'N/A')}{Colors.ENDC}")
            print(f"    Description: {vuln['description']}")
            print(f"    Impact: {vuln['impact']}")
            print(f"    Recommendation: {vuln['recommendation']}")
            
            if 'proof_of_concept' in vuln:
                print(f"\n    {Colors.CYAN}[PROOF OF CONCEPT]{Colors.ENDC}")
                poc = vuln['proof_of_concept']
                for key, val in poc.items():
                    if key == 'manual_test':
                        print(f"    {Colors.YELLOW}Manual Test:{Colors.ENDC}")
                        print(f"    {val}")
                    elif key in ['query', 'test_query', 'example']:
                        print(f"    {Colors.YELLOW}Test Query:{Colors.ENDC}")
                        print(f"    {val}")
                    elif key == 'payload':
                        print(f"    {Colors.YELLOW}Payload:{Colors.ENDC} {val}")
                    elif isinstance(val, (list, dict)) and len(str(val)) < 200:
                        print(f"    {key}: {val}")
            print()
    
    def run_scan(self, full_scan: bool = True):
        """Execute scan"""
        self.print_banner()
        
        print(f"{Colors.CYAN}[*] Starting comprehensive scan...{Colors.ENDC}\n")
        
        print(f"{Colors.BOLD}{Colors.BLUE}[PHASE 1] RECONNAISSANCE{Colors.ENDC}")
        self.test_endpoint_detection()
        self.test_graphiql_playground()
        self.test_http_methods()
        self.test_introspection()
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 2] AUTHENTICATION & AUTHORIZATION{Colors.ENDC}")
        self.test_idor()
        self.test_field_level_authorization()
        self.test_missing_auth_mutations()
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 3] INJECTION ATTACKS{Colors.ENDC}")
        self.test_sql_injection()
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 4] DOS & RESOURCE EXHAUSTION{Colors.ENDC}")
        self.test_query_depth_abuse()
        self.test_alias_overloading()
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 5] BUSINESS LOGIC{Colors.ENDC}")
        self.test_mass_assignment()
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 6] INFORMATION DISCLOSURE{Colors.ENDC}")
        self.test_sensitive_fields_exposure()
        self.test_error_message_leaks()
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}[PHASE 7] API SECURITY{Colors.ENDC}")
        self.test_cors_misconfiguration()
        
        self.generate_report()
        
        print(f"\n{Colors.GREEN}[✓] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
        print(f"{Colors.CYAN}[*] Total vulnerabilities: {len(self.vulnerabilities)}{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(description='SMART GraphQL Vulnerability Scanner by Sidharth Bahuguna')
    parser.add_argument('-u', '--url', required=True, help='Target GraphQL endpoint')
    parser.add_argument('-H', '--header', action='append', help='Custom headers (Key: Value)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout (default: 10)')
    parser.add_argument('-m', '--method', default='POST', choices=['POST', 'GET', 'PUT', 'PATCH'], help='HTTP method')
    parser.add_argument('--quick', action='store_true', help='Skip intensive tests')
    parser.add_argument('--full', action='store_true', help='Run all tests')
    
    args = parser.parse_args()
    
    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                headers[k.strip()] = v.strip()
    
    scanner = GraphQLScanner(args.url, headers, args.timeout, args.method)
    
    try:
        scanner.run_scan(full_scan=not args.quick)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {str(e)}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()