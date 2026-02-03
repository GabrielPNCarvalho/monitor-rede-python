#!/usr/bin/env python3
"""
Monitor de Rede Avançado - Python (VERSÃO MELHORADA)
Funcionalidades:
- Scroll completo em todas as listas
- DNS Reverso em thread separada
- Ordenação dinâmica de processos
- Sistema de busca/filtro por texto
- Gráficos ASCII de banda
- Tratamento robusto de erros de permissão
"""

import psutil
import curses
import time
import json
import csv
from datetime import datetime
from collections import defaultdict, deque
import socket
import threading
import os
import sys
import requests
from typing import Dict, List, Tuple, Set, Optional
import queue

class DNSResolver:
    """Resolvedor DNS assíncrono para não travar a UI"""
    def __init__(self, cache_size=100):
        self.cache = {}
        self.cache_size = cache_size
        self.resolve_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
    
    def _worker(self):
        """Thread worker para resolver DNS"""
        while self.running:
            try:
                ip = self.resolve_queue.get(timeout=0.5)
                if ip and ip not in self.cache:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        self.cache[ip] = hostname
                        self.result_queue.put((ip, hostname))
                        
                        # Limitar cache
                        if len(self.cache) > self.cache_size:
                            self.cache.pop(next(iter(self.cache)))
                    except (socket.herror, socket.gaierror, socket.timeout):
                        self.cache[ip] = None
            except queue.Empty:
                continue
            except Exception:
                pass
    
    def resolve_async(self, ip: str):
        """Solicita resolução DNS assíncrona"""
        if ip not in self.cache:
            try:
                self.resolve_queue.put_nowait(ip)
            except queue.Full:
                pass
    
    def get_hostname(self, ip: str) -> Optional[str]:
        """Obtém hostname do cache"""
        return self.cache.get(ip)
    
    def stop(self):
        """Para o resolver"""
        self.running = False

class ASCIIGraph:
    """Gerador de gráficos ASCII para visualização de tráfego"""
    
    @staticmethod
    def bar_graph(values: List[float], width: int, height: int, 
                  max_value: Optional[float] = None) -> List[str]:
        """
        Cria um gráfico de barras ASCII
        
        Args:
            values: Lista de valores a plotar
            width: Largura do gráfico
            height: Altura do gráfico
            max_value: Valor máximo (se None, usa o máximo dos valores)
        
        Returns:
            Lista de strings representando as linhas do gráfico
        """
        if not values or width <= 0 or height <= 0:
            return []
        
        # Ajustar valores para a largura
        if len(values) > width:
            # Pegar os últimos 'width' valores
            values = values[-width:]
        
        # Determinar valor máximo
        if max_value is None:
            max_value = max(values) if values else 1
        
        if max_value == 0:
            max_value = 1
        
        # Normalizar valores para altura
        normalized = [(v / max_value) * height for v in values]
        
        # Criar gráfico
        lines = []
        for row in range(height, 0, -1):
            line = ""
            for value in normalized:
                if value >= row:
                    line += "█"
                elif value >= row - 0.5:
                    line += "▄"
                else:
                    line += " "
            lines.append(line)
        
        return lines
    
    @staticmethod
    def sparkline(values: List[float], width: int) -> str:
        """
        Cria uma sparkline (mini-gráfico em uma linha)
        
        Args:
            values: Lista de valores
            width: Largura da sparkline
        
        Returns:
            String com a sparkline
        """
        if not values or width <= 0:
            return ""
        
        # Ajustar valores para a largura
        if len(values) > width:
            values = values[-width:]
        
        # Caracteres para sparkline (8 níveis)
        chars = " ▁▂▃▄▅▆▇█"
        
        max_val = max(values) if values else 1
        if max_val == 0:
            max_val = 1
        
        normalized = [(v / max_val) * (len(chars) - 1) for v in values]
        
        return "".join(chars[min(int(v), len(chars) - 1)] for v in normalized)

class NetworkMonitor:
    def __init__(self):
        self.connections = []
        self.processes = {}
        self.traffic_history = defaultdict(lambda: deque(maxlen=60))
        self.bandwidth_per_process = defaultdict(lambda: {'sent': 0, 'recv': 0})
        self.bandwidth_history = defaultdict(lambda: deque(maxlen=60))  # Histórico para gráficos
        self.suspicious_connections = []
        self.connection_history = deque(maxlen=1000)
        self.alerts = deque(maxlen=50)
        self.last_net_io = None
        self.last_process_io = {}
        self.blocked_ips = set()
        self.whitelist_ips = set()
        self.port_scan_detector = defaultdict(list)
        self.geo_cache = {}
        self.dns_resolver = DNSResolver()
        self.permission_warnings = set()  # Para não repetir avisos
        
        # Estatísticas
        self.stats = {
            'total_connections': 0,
            'established': 0,
            'listening': 0,
            'external': 0,
            'suspicious': 0,
            'total_sent': 0,
            'total_recv': 0,
            'alerts_count': 0,
            'access_denied_count': 0
        }
        
        # Configurações
        self.config = {
            'update_interval': 2,
            'alert_threshold_connections': 50,
            'alert_threshold_bandwidth': 10 * 1024 * 1024,
            'suspicious_ports': [4444, 5555, 6666, 31337, 12345],
            'enable_geo_lookup': True,
            'max_geo_requests': 10,
            'enable_dns_reverse': True
        }
        
        self.running = True
        self.current_view = 'connections'
        self.selected_index = 0
        self.scroll_offset = 0  # Para scroll
        self.filter_external_only = False
        self.filter_established_only = False
        self.search_term = ""  # Termo de busca
        self.search_active = False  # Modo de busca ativo
        
        # Ordenação de processos
        self.process_sort_by = 'connections'  # connections, cpu, memory, name
        self.process_sort_reverse = True
        
        # Inicializar IO counters
        try:
            self.last_net_io = psutil.net_io_counters(pernic=True)
        except Exception:
            self.last_net_io = {}
    
    def get_process_info(self, pid):
        """Obtém informações detalhadas do processo com tratamento de erros"""
        if pid in self.processes:
            return self.processes[pid]
        
        try:
            proc = psutil.Process(pid)
            
            # Tentar obter informações, com fallbacks
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = 'N/A'
            
            try:
                cmdline = ' '.join(proc.cmdline())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline = 'N/A'
            
            try:
                username = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                username = 'N/A'
            
            try:
                cpu_percent = proc.cpu_percent()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cpu_percent = 0.0
            
            try:
                memory_mb = proc.memory_info().rss / 1024 / 1024
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                memory_mb = 0.0
            
            try:
                num_threads = proc.num_threads()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                num_threads = 0
            
            try:
                create_time = datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S')
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                create_time = 'N/A'
            
            info = {
                'pid': pid,
                'name': proc.name(),
                'exe': exe,
                'cmdline': cmdline if cmdline else 'N/A',
                'username': username,
                'cpu_percent': cpu_percent,
                'memory_mb': memory_mb,
                'num_threads': num_threads,
                'create_time': create_time
            }
            self.processes[pid] = info
            return info
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None
        except psutil.AccessDenied:
            # Retornar informações parciais
            self.stats['access_denied_count'] += 1
            return {
                'pid': pid,
                'name': 'Access Denied',
                'exe': 'N/A',
                'cmdline': 'N/A',
                'username': 'N/A',
                'cpu_percent': 0.0,
                'memory_mb': 0.0,
                'num_threads': 0,
                'create_time': 'N/A'
            }
    
    def is_external_ip(self, ip):
        """Verifica se o IP é externo"""
        if ip in ['0.0.0.0', '*', '::', '127.0.0.1', 'localhost']:
            return False
        
        private_ranges = [
            '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
            '169.254.'
        ]
        
        for private in private_ranges:
            if ip.startswith(private):
                return False
        
        return True
    
    def is_suspicious_connection(self, conn, proc_info):
        """Detecta conexões suspeitas"""
        reasons = []
        
        if hasattr(conn, 'raddr') and conn.raddr:
            remote_port = conn.raddr.port
            if remote_port in self.config['suspicious_ports']:
                reasons.append(f"Porta suspeita: {remote_port}")
        
        if proc_info and proc_info['exe'] == 'N/A' and proc_info['name'] != 'Access Denied':
            reasons.append("Processo sem executável identificado")
        
        if proc_info and proc_info['pid'] != 'N/A':
            conn_count = sum(1 for c in self.connections if c.get('pid') == proc_info['pid'])
            if conn_count > self.config['alert_threshold_connections']:
                reasons.append(f"Muitas conexões: {conn_count}")
        
        if hasattr(conn, 'raddr') and conn.raddr and conn.raddr.ip in self.blocked_ips:
            reasons.append("IP bloqueado")
        
        return reasons
    
    def get_geo_location(self, ip):
        """Obtém geolocalização de um IP (com cache)"""
        if not self.config['enable_geo_lookup']:
            return None
        
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        
        if len(self.geo_cache) >= self.config['max_geo_requests']:
            return None
        
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    geo_info = f"{data.get('city', 'N/A')}, {data.get('country', 'N/A')}"
                    self.geo_cache[ip] = geo_info
                    return geo_info
        except:
            pass
        
        return None
    
    def detect_port_scan(self, ip):
        """Detecta possíveis port scans"""
        now = time.time()
        self.port_scan_detector[ip].append(now)
        
        self.port_scan_detector[ip] = [t for t in self.port_scan_detector[ip] if now - t < 60]
        
        if len(self.port_scan_detector[ip]) > 20:
            return True
        return False
    
    def update_network_data(self):
        """Atualiza dados de rede com tratamento de erros robusto"""
        self.connections = []
        access_denied_encountered = False
        
        try:
            connections = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            # Avisar usuário que precisa de permissões de admin
            if 'net_connections' not in self.permission_warnings:
                self.add_alert("⚠️ PERMISSÃO NEGADA: Execute como Administrador/root para ver todas as conexões", 'critical')
                self.permission_warnings.add('net_connections')
            connections = []
            access_denied_encountered = True
        except Exception as e:
            self.add_alert(f"Erro ao obter conexões: {str(e)[:50]}", 'warning')
            connections = []
        
        for conn in connections:
            if conn.status == 'NONE':
                continue
            
            try:
                proc_info = self.get_process_info(conn.pid) if conn.pid else None
                
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                
                is_external = False
                geo_location = None
                hostname = None
                
                if conn.raddr:
                    is_external = self.is_external_ip(conn.raddr.ip)
                    if is_external:
                        geo_location = self.get_geo_location(conn.raddr.ip)
                        
                        # DNS reverso assíncrono
                        if self.config['enable_dns_reverse']:
                            self.dns_resolver.resolve_async(conn.raddr.ip)
                            hostname = self.dns_resolver.get_hostname(conn.raddr.ip)
                        
                        if self.detect_port_scan(conn.raddr.ip):
                            self.add_alert(f"Possível port scan detectado de {conn.raddr.ip}", 'warning')
                
                suspicious_reasons = self.is_suspicious_connection(conn, proc_info)
                
                conn_data = {
                    'type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                    'local': local_addr,
                    'remote': remote_addr,
                    'status': conn.status,
                    'pid': conn.pid if conn.pid else 'N/A',
                    'process': proc_info['name'] if proc_info else 'N/A',
                    'is_external': is_external,
                    'geo_location': geo_location,
                    'hostname': hostname,
                    'suspicious': len(suspicious_reasons) > 0,
                    'suspicious_reasons': suspicious_reasons,
                    'proc_info': proc_info
                }
                
                self.connections.append(conn_data)
                
                self.connection_history.append({
                    'timestamp': datetime.now().isoformat(),
                    'connection': conn_data
                })
            except Exception as e:
                # Ignorar erros individuais de conexão
                continue
        
        self.update_statistics()
    
    def update_traffic_data(self):
        """Atualiza dados de tráfego de rede"""
        try:
            current_net_io = psutil.net_io_counters(pernic=True)
        except Exception:
            return
        
        timestamp = time.time()
        
        if self.last_net_io:
            for interface, stats in current_net_io.items():
                if interface in self.last_net_io:
                    last_stats = self.last_net_io[interface]
                    
                    sent_rate = max(0, stats.bytes_sent - last_stats.bytes_sent)
                    recv_rate = max(0, stats.bytes_recv - last_stats.bytes_recv)
                    
                    self.traffic_history[interface].append({
                        'timestamp': timestamp,
                        'sent': sent_rate,
                        'recv': recv_rate
                    })
        
        self.last_net_io = current_net_io
        
        # Atualizar tráfego por processo
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                io_counters = proc.io_counters()
                
                if pid in self.last_process_io:
                    last_io = self.last_process_io[pid]
                    sent = max(0, io_counters.write_bytes - last_io.write_bytes)
                    recv = max(0, io_counters.read_bytes - last_io.read_bytes)
                    
                    self.bandwidth_per_process[pid]['sent'] = sent
                    self.bandwidth_per_process[pid]['recv'] = recv
                    
                    # Adicionar ao histórico para gráficos
                    self.bandwidth_history[pid].append({
                        'timestamp': timestamp,
                        'sent': sent,
                        'recv': recv,
                        'total': sent + recv
                    })
                    
                    if sent > self.config['alert_threshold_bandwidth']:
                        proc_info = self.get_process_info(pid)
                        if proc_info and pid not in self.permission_warnings:
                            self.add_alert(f"Alto tráfego de saída: {proc_info['name']} ({self.format_bytes(sent)}/s)", 'warning')
                            self.permission_warnings.add(pid)
                
                self.last_process_io[pid] = io_counters
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue
    
    def update_statistics(self):
        """Atualiza estatísticas gerais"""
        self.stats['total_connections'] = len(self.connections)
        self.stats['established'] = sum(1 for c in self.connections if c['status'] == 'ESTABLISHED')
        self.stats['listening'] = sum(1 for c in self.connections if c['status'] == 'LISTEN')
        self.stats['external'] = sum(1 for c in self.connections if c['is_external'])
        self.stats['suspicious'] = sum(1 for c in self.connections if c['suspicious'])
        
        try:
            net_io = psutil.net_io_counters()
            self.stats['total_sent'] = net_io.bytes_sent
            self.stats['total_recv'] = net_io.bytes_recv
        except Exception:
            pass
    
    def add_alert(self, message, level='info'):
        """Adiciona um alerta"""
        alert = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'message': message,
            'level': level
        }
        self.alerts.append(alert)
        self.stats['alerts_count'] = len(self.alerts)
    
    def format_bytes(self, bytes_val):
        """Formata bytes em unidade legível"""
        if bytes_val == 0:
            return "0 B"
        elif bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val / 1024:.1f} KB"
        elif bytes_val < 1024 * 1024 * 1024:
            return f"{bytes_val / (1024 * 1024):.1f} MB"
        else:
            return f"{bytes_val / (1024 * 1024 * 1024):.1f} GB"
    
    def export_to_json(self, filename='network_monitor_export.json'):
        """Exporta dados para JSON"""
        data = {
            'export_time': datetime.now().isoformat(),
            'connections': self.connections,
            'statistics': self.stats,
            'alerts': list(self.alerts),
            'processes': list(self.processes.values())
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            return filename
        except Exception as e:
            self.add_alert(f"Erro ao exportar JSON: {str(e)[:30]}", 'warning')
            return None
    
    def export_to_csv(self, filename='network_monitor_export.csv'):
        """Exporta conexões para CSV"""
        try:
            with open(filename, 'w', newline='') as f:
                fieldnames = ['timestamp', 'type', 'local', 'remote', 'status', 'pid', 'process', 'is_external', 'suspicious']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                
                writer.writeheader()
                for conn in self.connections:
                    writer.writerow({
                        'timestamp': datetime.now().isoformat(),
                        'type': conn['type'],
                        'local': conn['local'],
                        'remote': conn['remote'],
                        'status': conn['status'],
                        'pid': conn['pid'],
                        'process': conn['process'],
                        'is_external': conn['is_external'],
                        'suspicious': conn['suspicious']
                    })
            return filename
        except Exception as e:
            self.add_alert(f"Erro ao exportar CSV: {str(e)[:30]}", 'warning')
            return None
    
    def get_filtered_connections(self):
        """Retorna conexões filtradas"""
        connections = self.connections
        
        if self.filter_external_only:
            connections = [c for c in connections if c['is_external']]
        
        if self.filter_established_only:
            connections = [c for c in connections if c['status'] == 'ESTABLISHED']
        
        # Filtro de busca
        if self.search_term:
            term = self.search_term.lower()
            connections = [c for c in connections if 
                          term in c['remote'].lower() or 
                          term in c['local'].lower() or 
                          term in c['process'].lower() or
                          term in str(c['pid']).lower() or
                          (c.get('hostname') and term in c['hostname'].lower())]
        
        return connections
    
    def get_sorted_processes(self):
        """Retorna processos ordenados"""
        # Agregar conexões por processo
        process_connections = defaultdict(int)
        for conn in self.connections:
            if conn['pid'] != 'N/A':
                process_connections[conn['pid']] += 1
        
        processes = list(self.processes.values())
        
        # Filtro de busca
        if self.search_term:
            term = self.search_term.lower()
            processes = [p for p in processes if 
                        term in p['name'].lower() or 
                        term in str(p['pid']).lower() or
                        term in p.get('exe', '').lower()]
        
        # Ordenar
        if self.process_sort_by == 'connections':
            processes.sort(key=lambda x: process_connections.get(x['pid'], 0), 
                          reverse=self.process_sort_reverse)
        elif self.process_sort_by == 'cpu':
            processes.sort(key=lambda x: x.get('cpu_percent', 0), 
                          reverse=self.process_sort_reverse)
        elif self.process_sort_by == 'memory':
            processes.sort(key=lambda x: x.get('memory_mb', 0), 
                          reverse=self.process_sort_reverse)
        elif self.process_sort_by == 'name':
            processes.sort(key=lambda x: x.get('name', '').lower(), 
                          reverse=self.process_sort_reverse)
        
        return processes, process_connections
    
    def cleanup(self):
        """Limpeza ao sair"""
        self.dns_resolver.stop()

class NetworkMonitorUI:
    def __init__(self, monitor):
        self.monitor = monitor
        self.stdscr = None
        self.input_buffer = ""  # Buffer para entrada de busca
        
    def run(self, stdscr):
        """Loop principal da UI"""
        self.stdscr = stdscr
        curses.curs_set(0)
        stdscr.nodelay(1)
        stdscr.timeout(100)
        
        # Cores
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_GREEN)
        
        last_update = 0
        
        # Mostrar aviso de permissões no início
        if os.name == 'nt':  # Windows
            self.monitor.add_alert("💡 Execute como Administrador para ver todas as conexões", 'info')
        else:  # Linux/Mac
            if os.geteuid() != 0:
                self.monitor.add_alert("💡 Execute com sudo para ver todas as conexões", 'info')
        
        while self.monitor.running:
            current_time = time.time()
            
            # Atualizar dados
            if current_time - last_update >= self.monitor.config['update_interval']:
                self.monitor.update_network_data()
                self.monitor.update_traffic_data()
                last_update = current_time
            
            # Desenhar interface
            try:
                self.draw_interface()
            except curses.error:
                pass
            
            # Processar input
            self.process_input()
            
            time.sleep(0.1)
    
    def draw_interface(self):
        """Desenha a interface"""
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()
        
        # Header
        self.draw_header()
        
        # Conteúdo baseado na view atual
        if self.monitor.current_view == 'connections':
            self.draw_connections_view()
        elif self.monitor.current_view == 'processes':
            self.draw_processes_view()
        elif self.monitor.current_view == 'traffic':
            self.draw_traffic_view()
        elif self.monitor.current_view == 'alerts':
            self.draw_alerts_view()
        elif self.monitor.current_view == 'stats':
            self.draw_stats_view()
        
        # Footer
        self.draw_footer()
        
        self.stdscr.refresh()
    
    def draw_header(self):
        """Desenha o cabeçalho"""
        height, width = self.stdscr.getmaxyx()
        
        title = "=== MONITOR DE REDE AVANÇADO v2.0 ==="
        self.stdscr.attron(curses.color_pair(6) | curses.A_BOLD)
        self.stdscr.addstr(0, (width - len(title)) // 2, title[:width-1])
        self.stdscr.attroff(curses.color_pair(6) | curses.A_BOLD)
        
        # Menu
        menu = "  [1]Conexões  [2]Processos  [3]Tráfego  [4]Alertas  [5]Stats  "
        self.stdscr.attron(curses.color_pair(4))
        self.stdscr.addstr(1, 0, menu[:width-1])
        self.stdscr.attroff(curses.color_pair(4))
        
        # Info
        info = f"Host: {socket.gethostname()} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        if len(info) < width - 2:
            self.stdscr.addstr(1, width - len(info) - 2, info)
        
        # Linha
        self.stdscr.addstr(2, 0, "=" * (width - 1))
        
        # Barra de busca se ativa
        if self.monitor.search_active:
            search_text = f"🔍 Busca: {self.monitor.search_term}_"
            self.stdscr.attron(curses.color_pair(7))
            try:
                self.stdscr.addstr(3, 0, search_text[:width-1] + " " * max(0, width - len(search_text) - 1))
            except curses.error:
                pass
            self.stdscr.attroff(curses.color_pair(7))
    
    def draw_connections_view(self):
        """Desenha a view de conexões com scroll"""
        height, width = self.stdscr.getmaxyx()
        start_y = 4 if self.monitor.search_active else 3
        
        # Filtros
        filters = []
        if self.monitor.filter_external_only:
            filters.append("EXTERNAS")
        if self.monitor.filter_established_only:
            filters.append("ESTABLISHED")
        if self.monitor.search_term:
            filters.append(f"BUSCA:'{self.monitor.search_term}'")
        
        filter_text = f"Filtros: {', '.join(filters)}" if filters else "Sem filtros (Pressione / para buscar)"
        self.stdscr.attron(curses.color_pair(3))
        self.stdscr.addstr(start_y, 0, filter_text[:width-1] + " " * max(0, width - len(filter_text) - 1))
        self.stdscr.attroff(curses.color_pair(3))
        start_y += 1
        
        # Cabeçalho
        header = f"{'TIPO':<6} {'LOCAL':<22} {'REMOTO':<22} {'STATUS':<12} {'PID':<8} {'PROC':<15} {'INFO':<20}"
        self.stdscr.attron(curses.A_BOLD)
        self.stdscr.addstr(start_y, 0, header[:width-1])
        self.stdscr.attroff(curses.A_BOLD)
        start_y += 1
        
        # Conexões com scroll
        connections = self.monitor.get_filtered_connections()
        max_lines = height - start_y - 4
        
        # Ajustar scroll se necessário
        if self.monitor.selected_index < self.monitor.scroll_offset:
            self.monitor.scroll_offset = self.monitor.selected_index
        elif self.monitor.selected_index >= self.monitor.scroll_offset + max_lines:
            self.monitor.scroll_offset = self.monitor.selected_index - max_lines + 1
        
        # Desenhar conexões visíveis
        visible_connections = connections[self.monitor.scroll_offset:self.monitor.scroll_offset + max_lines]
        
        for i, conn in enumerate(visible_connections):
            actual_index = i + self.monitor.scroll_offset
            
            # Preparar info extra
            info_extra = ""
            if conn.get('hostname'):
                info_extra = conn['hostname'][:19]
            elif conn.get('geo_location'):
                info_extra = conn['geo_location'][:19]
            
            line = f"{conn['type']:<6} {conn['local'][:21]:<22} {conn['remote'][:21]:<22} {conn['status'][:11]:<12} {str(conn['pid'])[:7]:<8} {conn['process'][:14]:<15} {info_extra:<20}"
            
            # Colorir
            if actual_index == self.monitor.selected_index:
                self.stdscr.attron(curses.color_pair(6))
            elif conn['suspicious']:
                self.stdscr.attron(curses.color_pair(2))
            elif conn['is_external'] and conn['status'] == 'ESTABLISHED':
                self.stdscr.attron(curses.color_pair(3))
            elif conn['is_external']:
                self.stdscr.attron(curses.color_pair(5))
            else:
                self.stdscr.attron(curses.color_pair(1))
            
            try:
                self.stdscr.addstr(start_y + i, 0, line[:width-1])
            except curses.error:
                pass
            
            self.stdscr.attroff(curses.color_pair(6))
            self.stdscr.attroff(curses.color_pair(1))
            self.stdscr.attroff(curses.color_pair(2))
            self.stdscr.attroff(curses.color_pair(3))
            self.stdscr.attroff(curses.color_pair(5))
        
        # Indicador de scroll
        if len(connections) > max_lines:
            scroll_info = f"[{self.monitor.scroll_offset + 1}-{min(self.monitor.scroll_offset + max_lines, len(connections))} de {len(connections)}]"
            try:
                self.stdscr.addstr(start_y + max_lines, width - len(scroll_info) - 2, scroll_info)
            except curses.error:
                pass
        
        # Detalhes da seleção
        if connections and self.monitor.selected_index < len(connections):
            self.draw_connection_details(connections[self.monitor.selected_index], height - 3)
    
    def draw_connection_details(self, conn, start_y):
        """Desenha detalhes da conexão selecionada"""
        height, width = self.stdscr.getmaxyx()
        
        details = f"→ {conn['remote']}"
        if conn.get('hostname'):
            details += f" ({conn['hostname']})"
        if conn['suspicious']:
            details += f" | ⚠️ SUSPEITO: {', '.join(conn['suspicious_reasons'])}"
        if conn['proc_info']:
            details += f" | Exe: {conn['proc_info'].get('exe', 'N/A')[:40]}"
        
        self.stdscr.attron(curses.color_pair(4))
        try:
            self.stdscr.addstr(start_y, 0, details[:width-1])
        except curses.error:
            pass
        self.stdscr.attroff(curses.color_pair(4))
    
    def draw_processes_view(self):
        """Desenha a view de processos com ordenação e scroll"""
        height, width = self.stdscr.getmaxyx()
        start_y = 4 if self.monitor.search_active else 3
        
        # Info de ordenação
        sort_symbols = {'connections': '⇅', 'cpu': '⇅', 'memory': '⇅', 'name': '⇅'}
        sort_symbols[self.monitor.process_sort_by] = '↓' if self.monitor.process_sort_reverse else '↑'
        
        sort_info = f"Ordenar: [C]Conexões{sort_symbols['connections']} [U]CPU{sort_symbols['cpu']} [M]Memória{sort_symbols['memory']} [N]Nome{sort_symbols['name']}"
        if self.monitor.search_term:
            sort_info += f" | Busca: '{self.monitor.search_term}'"
        
        self.stdscr.attron(curses.color_pair(3))
        self.stdscr.addstr(start_y, 0, sort_info[:width-1] + " " * max(0, width - len(sort_info) - 1))
        self.stdscr.attroff(curses.color_pair(3))
        start_y += 1
        
        # Cabeçalho
        header = f"{'PID':<8} {'PROCESSO':<20} {'CPU%':<8} {'MEM(MB)':<10} {'CONN':<6} {'BANDA ↓↑':<20} {'SPARK':<15}"
        self.stdscr.attron(curses.A_BOLD)
        self.stdscr.addstr(start_y, 0, header[:width-1])
        self.stdscr.attroff(curses.A_BOLD)
        start_y += 1
        
        processes, process_connections = self.monitor.get_sorted_processes()
        max_lines = height - start_y - 2
        
        # Ajustar scroll
        if self.monitor.selected_index < self.monitor.scroll_offset:
            self.monitor.scroll_offset = self.monitor.selected_index
        elif self.monitor.selected_index >= self.monitor.scroll_offset + max_lines:
            self.monitor.scroll_offset = self.monitor.selected_index - max_lines + 1
        
        visible_processes = processes[self.monitor.scroll_offset:self.monitor.scroll_offset + max_lines]
        
        for i, proc in enumerate(visible_processes):
            actual_index = i + self.monitor.scroll_offset
            pid = proc['pid']
            conn_count = process_connections.get(pid, 0)
            bandwidth = self.monitor.bandwidth_per_process.get(pid, {'sent': 0, 'recv': 0})
            
            # Sparkline de banda
            history = self.monitor.bandwidth_history.get(pid, deque())
            total_values = [h['total'] for h in history]
            sparkline = ASCIIGraph.sparkline(total_values, 14) if total_values else ""
            
            line = f"{pid:<8} {proc['name'][:19]:<20} {proc['cpu_percent']:<8.1f} {proc['memory_mb']:<10.1f} {conn_count:<6} "
            line += f"↓{self.monitor.format_bytes(bandwidth['recv'])[:6]}/↑{self.monitor.format_bytes(bandwidth['sent'])[:6]} {sparkline:<15}"
            
            if actual_index == self.monitor.selected_index:
                self.stdscr.attron(curses.color_pair(6))
            elif conn_count > 10:
                self.stdscr.attron(curses.color_pair(3))
            else:
                self.stdscr.attron(curses.color_pair(1))
            
            try:
                self.stdscr.addstr(start_y + i, 0, line[:width-1])
            except curses.error:
                pass
            
            self.stdscr.attroff(curses.color_pair(6))
            self.stdscr.attroff(curses.color_pair(1))
            self.stdscr.attroff(curses.color_pair(3))
        
        # Indicador de scroll
        if len(processes) > max_lines:
            scroll_info = f"[{self.monitor.scroll_offset + 1}-{min(self.monitor.scroll_offset + max_lines, len(processes))} de {len(processes)}]"
            try:
                self.stdscr.addstr(start_y + max_lines, width - len(scroll_info) - 2, scroll_info)
            except curses.error:
                pass
    
    def draw_traffic_view(self):
        """Desenha a view de tráfego com gráficos ASCII"""
        height, width = self.stdscr.getmaxyx()
        start_y = 4 if self.monitor.search_active else 3
        
        # Estatísticas gerais
        try:
            net_io = psutil.net_io_counters()
            
            self.stdscr.attron(curses.A_BOLD)
            self.stdscr.addstr(start_y, 0, "ESTATÍSTICAS GERAIS DE REDE:")
            self.stdscr.attroff(curses.A_BOLD)
            start_y += 2
            
            stats = [
                f"Total Enviado:  {self.monitor.format_bytes(net_io.bytes_sent)}",
                f"Total Recebido: {self.monitor.format_bytes(net_io.bytes_recv)}",
                f"Pacotes Enviados:  {net_io.packets_sent:,}",
                f"Pacotes Recebidos: {net_io.packets_recv:,}",
                f"Erros (in/out): {net_io.errin:,} / {net_io.errout:,}",
                f"Drops (in/out): {net_io.dropin:,} / {net_io.dropout:,}"
            ]
            
            for stat in stats:
                self.stdscr.addstr(start_y, 2, stat[:width-3])
                start_y += 1
        except Exception:
            pass
        
        start_y += 1
        
        # Tráfego por interface com gráficos
        self.stdscr.attron(curses.A_BOLD)
        self.stdscr.addstr(start_y, 0, "TRÁFEGO POR INTERFACE (últimos 60s):")
        self.stdscr.attroff(curses.A_BOLD)
        start_y += 2
        
        graph_height = 8
        graph_width = min(60, width - 25)
        
        for interface, history in list(self.monitor.traffic_history.items())[:3]:  # Primeiras 3 interfaces
            if history and start_y + graph_height + 3 < height - 3:
                last_sample = history[-1]
                
                # Nome da interface e taxa atual
                interface_line = f"{interface:<20} ↓ {self.monitor.format_bytes(last_sample['recv'])}/s  ↑ {self.monitor.format_bytes(last_sample['sent'])}/s"
                self.stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
                try:
                    self.stdscr.addstr(start_y, 2, interface_line[:width-3])
                except curses.error:
                    pass
                self.stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
                start_y += 1
                
                # Gráfico de recebimento
                recv_values = [h['recv'] for h in history]
                recv_graph = ASCIIGraph.bar_graph(recv_values, graph_width, graph_height // 2)
                
                self.stdscr.attron(curses.color_pair(1))
                for line in recv_graph:
                    try:
                        self.stdscr.addstr(start_y, 4, line[:width-5])
                    except curses.error:
                        pass
                    start_y += 1
                self.stdscr.attroff(curses.color_pair(1))
                
                # Gráfico de envio
                sent_values = [h['sent'] for h in history]
                sent_graph = ASCIIGraph.bar_graph(sent_values, graph_width, graph_height // 2)
                
                self.stdscr.attron(curses.color_pair(3))
                for line in sent_graph:
                    try:
                        self.stdscr.addstr(start_y, 4, line[:width-5])
                    except curses.error:
                        pass
                    start_y += 1
                self.stdscr.attroff(curses.color_pair(3))
                
                start_y += 1
    
    def draw_alerts_view(self):
        """Desenha a view de alertas com scroll"""
        height, width = self.stdscr.getmaxyx()
        start_y = 4 if self.monitor.search_active else 3
        
        # Cabeçalho
        header_text = f"ALERTAS DE SEGURANÇA ({len(self.monitor.alerts)} total)"
        if self.monitor.stats['access_denied_count'] > 0:
            header_text += f" | ⚠️ {self.monitor.stats['access_denied_count']} processos sem permissão"
        
        self.stdscr.attron(curses.A_BOLD)
        self.stdscr.addstr(start_y, 0, header_text[:width-1])
        self.stdscr.attroff(curses.A_BOLD)
        start_y += 2
        
        max_lines = height - start_y - 2
        alerts_list = list(self.monitor.alerts)
        
        # Ajustar scroll
        if self.monitor.selected_index < self.monitor.scroll_offset:
            self.monitor.scroll_offset = self.monitor.selected_index
        elif self.monitor.selected_index >= self.monitor.scroll_offset + max_lines:
            self.monitor.scroll_offset = self.monitor.selected_index - max_lines + 1
        
        visible_alerts = alerts_list[self.monitor.scroll_offset:self.monitor.scroll_offset + max_lines]
        
        for i, alert in enumerate(visible_alerts):
            color = curses.color_pair(1)
            if alert['level'] == 'warning':
                color = curses.color_pair(3)
            elif alert['level'] == 'critical':
                color = curses.color_pair(2) | curses.A_BOLD
            
            line = f"[{alert['timestamp']}] {alert['message']}"
            
            self.stdscr.attron(color)
            try:
                self.stdscr.addstr(start_y + i, 0, line[:width-1])
            except curses.error:
                pass
            self.stdscr.attroff(color)
        
        # Indicador de scroll
        if len(alerts_list) > max_lines:
            scroll_info = f"[{self.monitor.scroll_offset + 1}-{min(self.monitor.scroll_offset + max_lines, len(alerts_list))} de {len(alerts_list)}]"
            try:
                self.stdscr.addstr(start_y + max_lines, width - len(scroll_info) - 2, scroll_info)
            except curses.error:
                pass
    
    def draw_stats_view(self):
        """Desenha a view de estatísticas"""
        height, width = self.stdscr.getmaxyx()
        start_y = 4 if self.monitor.search_active else 3
        
        self.stdscr.attron(curses.A_BOLD)
        self.stdscr.addstr(start_y, 0, "ESTATÍSTICAS DO MONITOR:")
        self.stdscr.attroff(curses.A_BOLD)
        start_y += 2
        
        stats = [
            f"Total de Conexões:       {self.monitor.stats['total_connections']}",
            f"Conexões Estabelecidas:  {self.monitor.stats['established']}",
            f"Portas Escutando:        {self.monitor.stats['listening']}",
            f"Conexões Externas:       {self.monitor.stats['external']}",
            f"Conexões Suspeitas:      {self.monitor.stats['suspicious']}",
            "",
            f"Total de Alertas:        {self.monitor.stats['alerts_count']}",
            f"Processos Monitorados:   {len(self.monitor.processes)}",
            f"Histórico de Conexões:   {len(self.monitor.connection_history)}",
            f"Cache DNS:               {len(self.monitor.dns_resolver.cache)} entradas",
            f"Cache Geo:               {len(self.monitor.geo_cache)} entradas",
            "",
            f"Tráfego Total Enviado:   {self.monitor.format_bytes(self.monitor.stats['total_sent'])}",
            f"Tráfego Total Recebido:  {self.monitor.format_bytes(self.monitor.stats['total_recv'])}",
            "",
            f"Processos sem Permissão: {self.monitor.stats['access_denied_count']}",
        ]
        
        for i, stat in enumerate(stats):
            if stat:
                self.stdscr.attron(curses.color_pair(4))
                try:
                    self.stdscr.addstr(start_y + i, 2, stat[:width-3])
                except curses.error:
                    pass
                self.stdscr.attroff(curses.color_pair(4))
        
        # Adicionar legenda de permissões
        start_y += len(stats) + 2
        
        if self.monitor.stats['access_denied_count'] > 0:
            self.stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
            perm_msg = "⚠️ Execute como Administrador/root para acesso completo"
            try:
                self.stdscr.addstr(start_y, 2, perm_msg[:width-3])
            except curses.error:
                pass
            self.stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
    
    def draw_footer(self):
        """Desenha o rodapé"""
        height, width = self.stdscr.getmaxyx()
        
        if self.monitor.current_view == 'processes':
            footer = "  Q:Sair  R:Refresh  /:Buscar  C/U/M/N:Ordenar  ↑↓:Navegar  PgUp/PgDn:Scroll  "
        else:
            footer = "  Q:Sair  R:Refresh  E:JSON  C:CSV  /:Buscar  F:Filtro  ↑↓:Navegar  PgUp/PgDn:Scroll  "
        
        self.stdscr.attron(curses.color_pair(6))
        try:
            self.stdscr.addstr(height - 1, 0, footer[:width-1] + " " * max(0, width - len(footer) - 1))
        except curses.error:
            pass
        self.stdscr.attroff(curses.color_pair(6))
    
    def process_input(self):
        """Processa entrada do usuário"""
        try:
            key = self.stdscr.getch()
            
            # Modo de busca
            if self.monitor.search_active:
                if key == 27:  # ESC
                    self.monitor.search_active = False
                    self.monitor.search_term = ""
                    self.monitor.selected_index = 0
                    self.monitor.scroll_offset = 0
                elif key == 10 or key == curses.KEY_ENTER:  # Enter
                    self.monitor.search_active = False
                    self.monitor.selected_index = 0
                    self.monitor.scroll_offset = 0
                elif key == curses.KEY_BACKSPACE or key == 127:
                    if self.monitor.search_term:
                        self.monitor.search_term = self.monitor.search_term[:-1]
                elif 32 <= key <= 126:  # Caracteres imprimíveis
                    self.monitor.search_term += chr(key)
                return
            
            # Comandos normais
            if key == ord('q') or key == ord('Q'):
                self.monitor.running = False
            elif key == ord('r') or key == ord('R'):
                self.monitor.update_network_data()
                self.monitor.update_traffic_data()
            elif key == ord('/'):
                self.monitor.search_active = True
                self.monitor.search_term = ""
            elif key == ord('1'):
                self.monitor.current_view = 'connections'
                self.monitor.selected_index = 0
                self.monitor.scroll_offset = 0
            elif key == ord('2'):
                self.monitor.current_view = 'processes'
                self.monitor.selected_index = 0
                self.monitor.scroll_offset = 0
            elif key == ord('3'):
                self.monitor.current_view = 'traffic'
                self.monitor.scroll_offset = 0
            elif key == ord('4'):
                self.monitor.current_view = 'alerts'
                self.monitor.selected_index = 0
                self.monitor.scroll_offset = 0
            elif key == ord('5'):
                self.monitor.current_view = 'stats'
                self.monitor.scroll_offset = 0
            elif key == ord('e') or key == ord('E'):
                filename = self.monitor.export_to_json()
                if filename:
                    self.monitor.add_alert(f"Dados exportados para {filename}", 'info')
            elif key == ord('c') or key == ord('C'):
                if self.monitor.current_view == 'processes':
                    # Ordenar por conexões
                    if self.monitor.process_sort_by == 'connections':
                        self.monitor.process_sort_reverse = not self.monitor.process_sort_reverse
                    else:
                        self.monitor.process_sort_by = 'connections'
                        self.monitor.process_sort_reverse = True
                    self.monitor.selected_index = 0
                    self.monitor.scroll_offset = 0
                else:
                    filename = self.monitor.export_to_csv()
                    if filename:
                        self.monitor.add_alert(f"Dados exportados para {filename}", 'info')
            elif key == ord('u') or key == ord('U'):
                if self.monitor.current_view == 'processes':
                    if self.monitor.process_sort_by == 'cpu':
                        self.monitor.process_sort_reverse = not self.monitor.process_sort_reverse
                    else:
                        self.monitor.process_sort_by = 'cpu'
                        self.monitor.process_sort_reverse = True
                    self.monitor.selected_index = 0
                    self.monitor.scroll_offset = 0
            elif key == ord('m') or key == ord('M'):
                if self.monitor.current_view == 'processes':
                    if self.monitor.process_sort_by == 'memory':
                        self.monitor.process_sort_reverse = not self.monitor.process_sort_reverse
                    else:
                        self.monitor.process_sort_by = 'memory'
                        self.monitor.process_sort_reverse = True
                    self.monitor.selected_index = 0
                    self.monitor.scroll_offset = 0
            elif key == ord('n') or key == ord('N'):
                if self.monitor.current_view == 'processes':
                    if self.monitor.process_sort_by == 'name':
                        self.monitor.process_sort_reverse = not self.monitor.process_sort_reverse
                    else:
                        self.monitor.process_sort_by = 'name'
                        self.monitor.process_sort_reverse = True
                    self.monitor.selected_index = 0
                    self.monitor.scroll_offset = 0
            elif key == ord('f') or key == ord('F'):
                self.monitor.filter_external_only = not self.monitor.filter_external_only
                self.monitor.selected_index = 0
                self.monitor.scroll_offset = 0
            elif key == ord('s') or key == ord('S'):
                self.monitor.filter_established_only = not self.monitor.filter_established_only
                self.monitor.selected_index = 0
                self.monitor.scroll_offset = 0
            elif key == curses.KEY_UP:
                if self.monitor.selected_index > 0:
                    self.monitor.selected_index -= 1
            elif key == curses.KEY_DOWN:
                if self.monitor.current_view == 'connections':
                    max_index = len(self.monitor.get_filtered_connections()) - 1
                elif self.monitor.current_view == 'processes':
                    max_index = len(self.monitor.get_sorted_processes()[0]) - 1
                elif self.monitor.current_view == 'alerts':
                    max_index = len(self.monitor.alerts) - 1
                else:
                    max_index = 0
                
                if self.monitor.selected_index < max_index:
                    self.monitor.selected_index += 1
            elif key == curses.KEY_PPAGE:  # Page Up
                self.monitor.selected_index = max(0, self.monitor.selected_index - 10)
            elif key == curses.KEY_NPAGE:  # Page Down
                if self.monitor.current_view == 'connections':
                    max_index = len(self.monitor.get_filtered_connections()) - 1
                elif self.monitor.current_view == 'processes':
                    max_index = len(self.monitor.get_sorted_processes()[0]) - 1
                elif self.monitor.current_view == 'alerts':
                    max_index = len(self.monitor.alerts) - 1
                else:
                    max_index = 0
                
                self.monitor.selected_index = min(max_index, self.monitor.selected_index + 10)
            elif key == curses.KEY_HOME:
                self.monitor.selected_index = 0
                self.monitor.scroll_offset = 0
            elif key == curses.KEY_END:
                if self.monitor.current_view == 'connections':
                    self.monitor.selected_index = len(self.monitor.get_filtered_connections()) - 1
                elif self.monitor.current_view == 'processes':
                    self.monitor.selected_index = len(self.monitor.get_sorted_processes()[0]) - 1
                elif self.monitor.current_view == 'alerts':
                    self.monitor.selected_index = len(self.monitor.alerts) - 1
        except:
            pass

def main():
    """Função principal"""
    print("=" * 60)
    print("Monitor de Rede Avançado v2.0")
    print("=" * 60)
    print()
    
    # Verificar permissões
    if os.name == 'nt':  # Windows
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("⚠️  AVISO: Execute como Administrador para acesso completo")
            print("   Algumas informações podem não estar disponíveis")
            print()
    else:  # Linux/Mac
        if os.geteuid() != 0:
            print("⚠️  AVISO: Execute com sudo para acesso completo")
            print("   sudo python3 network_monitor.py")
            print("   Algumas informações podem não estar disponíveis")
            print()
    
    print("Iniciando monitor...")
    print("Coletando informações iniciais...")
    
    monitor = NetworkMonitor()
    
    # Primeira coleta
    monitor.update_network_data()
    monitor.update_traffic_data()
    
    print(f"✓ {len(monitor.connections)} conexões detectadas")
    print(f"✓ {len(monitor.processes)} processos identificados")
    print()
    print("Iniciando interface...")
    print()
    
    # Iniciar UI
    ui = NetworkMonitorUI(monitor)
    
    try:
        curses.wrapper(ui.run)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.cleanup()
    
    print("\nMonitor encerrado.")
    print(f"Total de conexões monitoradas: {monitor.stats['total_connections']}")
    print(f"Alertas gerados: {monitor.stats['alerts_count']}")
    if monitor.stats['access_denied_count'] > 0:
        print(f"⚠️  Processos sem permissão: {monitor.stats['access_denied_count']}")
        if os.name == 'nt':
            print("   Execute como Administrador para acesso completo")
        else:
            print("   Execute com sudo para acesso completo")

if __name__ == "__main__":
    main()
