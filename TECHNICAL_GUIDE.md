# 🔧 Guia de Implementação Técnica - Network Monitor v2.0

## 📝 Índice
1. [Arquitetura do Sistema](#arquitetura)
2. [Implementação de Scroll](#scroll)
3. [DNS Reverso Assíncrono](#dns)
4. [Sistema de Ordenação](#ordenacao)
5. [Sistema de Busca](#busca)
6. [Gráficos ASCII](#graficos)
7. [Tratamento de Erros](#erros)

---

<a name="arquitetura"></a>
## 1. Arquitetura do Sistema

### Componentes Principais

```
┌─────────────────────────────────────────┐
│         NetworkMonitorUI                │
│  (Interface Curses + Input Handler)     │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│         NetworkMonitor                  │
│  (Lógica de Negócio + Dados)           │
└─────┬──────────┬──────────┬─────────────┘
      │          │          │
      ▼          ▼          ▼
┌──────────┐ ┌──────────┐ ┌──────────────┐
│  DNS     │ │  ASCII   │ │   psutil     │
│ Resolver │ │  Graph   │ │  (Sistema)   │
└──────────┘ └──────────┘ └──────────────┘
```

### Classes Principais

#### **DNSResolver**
- Thread worker separada
- Queue para requisições
- Cache LRU de 100 entradas
- Não bloqueia UI

#### **ASCIIGraph**
- Métodos estáticos
- Geração de bar graphs
- Geração de sparklines
- Normalização automática

#### **NetworkMonitor**
- Gerenciamento de estado
- Coleta de dados
- Filtros e buscas
- Estatísticas

#### **NetworkMonitorUI**
- Renderização curses
- Gerenciamento de input
- Controle de scroll
- Desenho de views

---

<a name="scroll"></a>
## 2. Implementação de Scroll

### Conceito

O scroll permite visualizar listas maiores que a tela:

```
Dados:      [Item 0, Item 1, Item 2, ..., Item 99]
Tela:       Altura de 20 linhas
Visível:    Items [scroll_offset : scroll_offset + 20]
```

### Código de Scroll

```python
# Variáveis de estado
self.selected_index = 0      # Índice do item selecionado
self.scroll_offset = 0       # Primeiro item visível

# Calcular altura disponível
max_lines = height - start_y - 4

# Ajustar scroll automaticamente
if self.selected_index < self.scroll_offset:
    # Seleção está acima da área visível
    self.scroll_offset = self.selected_index
elif self.selected_index >= self.scroll_offset + max_lines:
    # Seleção está abaixo da área visível
    self.scroll_offset = self.selected_index - max_lines + 1

# Obter itens visíveis
visible_items = items[self.scroll_offset:self.scroll_offset + max_lines]

# Desenhar itens
for i, item in enumerate(visible_items):
    actual_index = i + self.scroll_offset
    # Desenhar item...
```

### Indicador de Scroll

```python
if len(items) > max_lines:
    start = self.scroll_offset + 1
    end = min(self.scroll_offset + max_lines, len(items))
    total = len(items)
    
    scroll_info = f"[{start}-{end} de {total}]"
    stdscr.addstr(y, x, scroll_info)
```

### Teclas de Navegação

```python
# Navegação básica
elif key == curses.KEY_UP:
    if self.selected_index > 0:
        self.selected_index -= 1

elif key == curses.KEY_DOWN:
    max_index = len(items) - 1
    if self.selected_index < max_index:
        self.selected_index += 1

# Scroll rápido
elif key == curses.KEY_PPAGE:  # Page Up
    self.selected_index = max(0, self.selected_index - 10)

elif key == curses.KEY_NPAGE:  # Page Down
    max_index = len(items) - 1
    self.selected_index = min(max_index, self.selected_index + 10)

# Extremos
elif key == curses.KEY_HOME:
    self.selected_index = 0
    self.scroll_offset = 0

elif key == curses.KEY_END:
    self.selected_index = len(items) - 1
```

---

<a name="dns"></a>
## 3. DNS Reverso Assíncrono

### Problema sem Threading

```python
# BLOQUEANTE - Trava a UI
for ip in ips:
    hostname = socket.gethostbyaddr(ip)[0]  # Pode demorar 1-5s!
    # UI congelada durante lookup
```

### Solução com Threading

```python
class DNSResolver:
    def __init__(self):
        self.cache = {}
        self.resolve_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.running = True
        
        # Thread worker
        self.worker_thread = threading.Thread(
            target=self._worker, 
            daemon=True
        )
        self.worker_thread.start()
    
    def _worker(self):
        """Roda em thread separada"""
        while self.running:
            try:
                # Pegar IP da fila
                ip = self.resolve_queue.get(timeout=0.5)
                
                # Resolver (pode demorar)
                hostname = socket.gethostbyaddr(ip)[0]
                
                # Salvar no cache
                self.cache[ip] = hostname
                
            except queue.Empty:
                continue
            except:
                self.cache[ip] = None
    
    def resolve_async(self, ip: str):
        """Solicita resolução (não bloqueia)"""
        if ip not in self.cache:
            self.resolve_queue.put_nowait(ip)
    
    def get_hostname(self, ip: str):
        """Obtém do cache (instantâneo)"""
        return self.cache.get(ip)
```

### Uso na UI

```python
# 1. Solicitar resolução (não bloqueia)
if is_external:
    self.dns_resolver.resolve_async(ip)

# 2. Obter resultado se disponível
hostname = self.dns_resolver.get_hostname(ip)

# 3. Exibir (hostname ou None)
if hostname:
    display_text = f"{ip} ({hostname})"
```

### Cache LRU

```python
def _worker(self):
    # ... resolver DNS ...
    
    self.cache[ip] = hostname
    
    # Limitar tamanho do cache
    if len(self.cache) > self.cache_size:
        # Remover entrada mais antiga (FIFO)
        self.cache.pop(next(iter(self.cache)))
```

---

<a name="ordenacao"></a>
## 4. Sistema de Ordenação Dinâmica

### Estado de Ordenação

```python
# Armazenar critério e direção
self.process_sort_by = 'connections'  # connections, cpu, memory, name
self.process_sort_reverse = True      # True = descendente
```

### Função de Ordenação

```python
def get_sorted_processes(self):
    processes = list(self.processes.values())
    
    # Ordenar por critério
    if self.process_sort_by == 'connections':
        processes.sort(
            key=lambda x: process_connections.get(x['pid'], 0),
            reverse=self.process_sort_reverse
        )
    elif self.process_sort_by == 'cpu':
        processes.sort(
            key=lambda x: x.get('cpu_percent', 0),
            reverse=self.process_sort_reverse
        )
    elif self.process_sort_by == 'memory':
        processes.sort(
            key=lambda x: x.get('memory_mb', 0),
            reverse=self.process_sort_reverse
        )
    elif self.process_sort_by == 'name':
        processes.sort(
            key=lambda x: x.get('name', '').lower(),
            reverse=self.process_sort_reverse
        )
    
    return processes
```

### Alternância de Ordem

```python
elif key == ord('c'):
    if self.process_sort_by == 'connections':
        # Já está ordenando por conexões, inverter
        self.process_sort_reverse = not self.process_sort_reverse
    else:
        # Mudar para conexões
        self.process_sort_by = 'connections'
        self.process_sort_reverse = True  # Começar descendente
    
    # Resetar navegação
    self.selected_index = 0
    self.scroll_offset = 0
```

### Indicadores Visuais

```python
# Preparar símbolos
sort_symbols = {
    'connections': '⇅',
    'cpu': '⇅',
    'memory': '⇅',
    'name': '⇅'
}

# Atualizar símbolo da coluna ativa
if self.process_sort_reverse:
    sort_symbols[self.process_sort_by] = '↓'
else:
    sort_symbols[self.process_sort_by] = '↑'

# Exibir no header
header = f"Conexões{sort_symbols['connections']} CPU{sort_symbols['cpu']}"
```

---

<a name="busca"></a>
## 5. Sistema de Busca/Filtro

### Estado de Busca

```python
self.search_term = ""       # Termo atual
self.search_active = False  # Modo de entrada ativo
```

### Captura de Input

```python
def process_input(self):
    key = self.stdscr.getch()
    
    # Ativar busca
    if key == ord('/'):
        self.search_active = True
        self.search_term = ""
        return
    
    # Modo de busca ativo
    if self.search_active:
        if key == 27:  # ESC
            self.search_active = False
            self.search_term = ""
        
        elif key == curses.KEY_BACKSPACE or key == 127:
            if self.search_term:
                self.search_term = self.search_term[:-1]
        
        elif 32 <= key <= 126:  # Caracteres imprimíveis
            self.search_term += chr(key)
        
        return  # Não processar outras teclas
```

### Aplicação de Filtro

```python
def get_filtered_connections(self):
    connections = self.connections
    
    # Filtros booleanos
    if self.filter_external_only:
        connections = [c for c in connections if c['is_external']]
    
    # Filtro de busca (case-insensitive)
    if self.search_term:
        term = self.search_term.lower()
        connections = [c for c in connections if 
            term in c['remote'].lower() or 
            term in c['local'].lower() or 
            term in c['process'].lower() or
            term in str(c['pid']).lower() or
            (c.get('hostname') and term in c['hostname'].lower())
        ]
    
    return connections
```

### Barra de Busca Visual

```python
if self.search_active:
    search_text = f"🔍 Busca: {self.search_term}_"
    
    # Fundo colorido
    self.stdscr.attron(curses.color_pair(7))  # Preto em verde
    self.stdscr.addstr(3, 0, search_text + " " * (width - len(search_text)))
    self.stdscr.attroff(curses.color_pair(7))
```

### Reset ao Mudar View

```python
elif key == ord('1'):
    self.current_view = 'connections'
    
    # Resetar navegação ao mudar view
    self.selected_index = 0
    self.scroll_offset = 0
```

---

<a name="graficos"></a>
## 6. Gráficos ASCII

### Bar Graph - Conceito

```
Valores: [10, 25, 40, 30, 15]
Max: 40
Altura: 4

Normalizado: [1.0, 2.5, 4.0, 3.0, 1.5]

Gráfico:
       █      
    █  █  █   
 █  █  █  █   
 █  █  █  █  █
 0  1  2  3  4
```

### Implementação de Bar Graph

```python
@staticmethod
def bar_graph(values: List[float], width: int, height: int):
    # Ajustar para largura
    if len(values) > width:
        values = values[-width:]  # Últimos N valores
    
    # Normalizar para altura
    max_value = max(values) if values else 1
    if max_value == 0:
        max_value = 1
    
    normalized = [(v / max_value) * height for v in values]
    
    # Criar linhas (de cima para baixo)
    lines = []
    for row in range(height, 0, -1):
        line = ""
        for value in normalized:
            if value >= row:
                line += "█"        # Bloco cheio
            elif value >= row - 0.5:
                line += "▄"        # Meio bloco
            else:
                line += " "        # Vazio
        lines.append(line)
    
    return lines
```

### Sparkline - Conceito

```
Valores: [5, 10, 20, 15, 8]
Caracteres: " ▁▂▃▄▅▆▇█"

Normalizado para 0-8:
[1.6, 3.2, 6.4, 4.8, 2.6]

Resultado: "▂▃▆▅▃"
```

### Implementação de Sparkline

```python
@staticmethod
def sparkline(values: List[float], width: int) -> str:
    if not values:
        return ""
    
    # Ajustar para largura
    if len(values) > width:
        values = values[-width:]
    
    # Caracteres graduados (0-8)
    chars = " ▁▂▃▄▅▆▇█"
    
    # Normalizar para 0-(len(chars)-1)
    max_val = max(values) if values else 1
    normalized = [(v / max_val) * (len(chars) - 1) for v in values]
    
    # Mapear para caracteres
    return "".join(
        chars[min(int(v), len(chars) - 1)] 
        for v in normalized
    )
```

### Uso na View de Tráfego

```python
# Obter valores históricos
recv_values = [h['recv'] for h in history]

# Gerar gráfico
graph = ASCIIGraph.bar_graph(recv_values, 60, 8)

# Desenhar
for line in graph:
    stdscr.addstr(y, x, line)
    y += 1
```

### Uso na View de Processos

```python
# Obter histórico de banda
history = self.bandwidth_history.get(pid, deque())
total_values = [h['total'] for h in history]

# Gerar sparkline
sparkline = ASCIIGraph.sparkline(total_values, 14)

# Incluir na linha
line = f"{pid} {name} {sparkline}"
```

---

<a name="erros"></a>
## 7. Tratamento de Erros de Permissão

### Problema

```python
# Sem tratamento - programa crasha
connections = psutil.net_connections()  # AccessDenied!
```

### Detecção no Início

```python
import os
import ctypes  # Windows

# Linux/Mac
if os.geteuid() != 0:
    print("⚠️ Execute com sudo")

# Windows
is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
if not is_admin:
    print("⚠️ Execute como Administrador")
```

### Tratamento Durante Execução

```python
def update_network_data(self):
    try:
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        # Avisar usuário apenas uma vez
        if 'net_connections' not in self.permission_warnings:
            self.add_alert(
                "⚠️ PERMISSÃO NEGADA: Execute como Admin", 
                'critical'
            )
            self.permission_warnings.add('net_connections')
        connections = []
    except Exception as e:
        self.add_alert(f"Erro: {str(e)[:50]}", 'warning')
        connections = []
```

### Informações Parciais

```python
def get_process_info(self, pid):
    try:
        proc = psutil.Process(pid)
        
        # Tentar cada campo individualmente
        try:
            exe = proc.exe()
        except psutil.AccessDenied:
            exe = 'N/A'
        
        try:
            username = proc.username()
        except psutil.AccessDenied:
            username = 'N/A'
        
        # ... continuar para outros campos
        
        return {
            'pid': pid,
            'name': proc.name(),  # Geralmente funciona
            'exe': exe,
            'username': username,
            # ...
        }
    
    except psutil.AccessDenied:
        # Retornar estrutura mínima
        self.stats['access_denied_count'] += 1
        return {
            'pid': pid,
            'name': 'Access Denied',
            'exe': 'N/A',
            # ...
        }
```

### Contador de Problemas

```python
self.stats['access_denied_count'] = 0

# Incrementar ao encontrar problema
except psutil.AccessDenied:
    self.stats['access_denied_count'] += 1

# Exibir na UI
stats_text = f"Processos sem Permissão: {self.stats['access_denied_count']}"
```

### Evitar Spam de Alertas

```python
self.permission_warnings = set()

# Só alertar uma vez por tipo
if 'net_connections' not in self.permission_warnings:
    self.add_alert("Permissão negada", 'critical')
    self.permission_warnings.add('net_connections')
```

---

## 📊 Fluxo de Dados Completo

```
1. Inicialização
   ├─ Criar DNSResolver (thread)
   ├─ Verificar permissões
   └─ Primeira coleta de dados

2. Loop Principal (a cada 2s)
   ├─ update_network_data()
   │  ├─ psutil.net_connections()
   │  ├─ Para cada conexão:
   │  │  ├─ get_process_info()
   │  │  ├─ is_external_ip()
   │  │  ├─ resolve_async() [DNS]
   │  │  └─ is_suspicious()
   │  └─ update_statistics()
   │
   ├─ update_traffic_data()
   │  ├─ psutil.net_io_counters()
   │  ├─ Calcular deltas
   │  └─ Adicionar ao histórico
   │
   └─ draw_interface()
      ├─ draw_header()
      ├─ draw_[current_view]()
      │  ├─ get_filtered_*()
      │  ├─ Aplicar scroll
      │  ├─ Gerar gráficos
      │  └─ Desenhar itens
      └─ draw_footer()

3. Input Handler
   ├─ Teclas de navegação
   ├─ Teclas de view
   ├─ Modo de busca
   └─ Comandos especiais

4. Thread DNS (paralela)
   ├─ Aguardar IP na queue
   ├─ Resolver hostname
   └─ Salvar no cache
```

---

## 🎯 Otimizações Implementadas

### 1. Cache Agressivo
- DNS: 100 entradas
- Geo: 10 entradas
- Processos: Todos em memória

### 2. Threading
- DNS em thread separada
- UI nunca bloqueia

### 3. Deques com Limites
- Histórico: 60 entradas
- Alertas: 50 entradas
- Conexões: 1000 entradas

### 4. Normalização de Dados
- Gráficos normalizados automaticamente
- Valores extremos não quebram visualização

### 5. Renderização Eficiente
- Apenas itens visíveis são desenhados
- Scroll evita redesenhar tudo

---

## 🔍 Debugging

### Logs de Debug

```python
# Em desenvolvimento, adicionar:
import logging

logging.basicConfig(
    filename='netmonitor.log',
    level=logging.DEBUG
)

# No código:
logging.debug(f"Scroll: {self.scroll_offset}, Selected: {self.selected_index}")
```

### Teste de Componentes

```python
# Testar gráficos isoladamente
if __name__ == "__main__":
    values = [10, 20, 30, 25, 15]
    graph = ASCIIGraph.bar_graph(values, 60, 10)
    for line in graph:
        print(line)
```

---

## 📚 Referências

- **psutil**: https://psutil.readthedocs.io/
- **curses**: https://docs.python.org/3/library/curses.html
- **threading**: https://docs.python.org/3/library/threading.html
- **queue**: https://docs.python.org/3/library/queue.html

---

**Todas as 6 funcionalidades implementadas e documentadas!** 🎉
