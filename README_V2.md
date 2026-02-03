# 🌐 Monitor de Rede Avançado v2.0 - Python

## 🆕 NOVIDADES DA VERSÃO 2.0

### ✨ 6 Melhorias Implementadas:

1. **📜 Scroll Completo em Todas as Listas**
   - Suporte para centenas/milhares de conexões
   - Navegação com setas, Page Up/Down, Home/End
   - Indicador visual de posição no scroll
   - Scroll automático ao navegar

2. **🌐 DNS Reverso Assíncrono**
   - Resolução de hostnames em thread separada
   - Não trava a interface durante lookups
   - Cache inteligente de 100 entradas
   - Exibição automática ao lado do IP

3. **🔄 Ordenação Dinâmica de Processos**
   - Ordenar por: Conexões, CPU, Memória ou Nome
   - Alternar ordem crescente/decrescente
   - Teclas rápidas: C/U/M/N
   - Indicadores visuais de ordenação (↑↓)

4. **🔍 Sistema de Busca/Filtro por Texto**
   - Busca em tempo real
   - Filtra conexões por IP, processo, PID, hostname
   - Filtra processos por nome, PID, executável
   - Tecla `/` para ativar, ESC para sair

5. **📊 Gráficos ASCII de Banda**
   - Gráficos de barras na view de tráfego
   - Sparklines na view de processos
   - Histórico de 60 segundos
   - Visualização de oscilação em tempo real

6. **🛡️ Tratamento Robusto de Erros de Permissão**
   - Detecta automaticamente falta de privilégios
   - Alertas claros para Windows e Linux
   - Informações parciais mesmo sem admin
   - Contador de processos sem acesso

---

## 📋 Requisitos

### Sistema Operacional
- Linux (recomendado - melhor suporte)
- macOS (suportado)
- Windows (suportado - requer Administrador)

### Python
- Python 3.7 ou superior

### Dependências
```bash
pip install psutil requests
```

---

## 🔧 Instalação

### Opção 1: Instalação Rápida (Linux/Mac)
```bash
chmod +x install.sh
./install.sh
```

### Opção 2: Instalação Manual
```bash
# Instalar dependências
pip install -r requirements.txt

# Executar (modo limitado)
python3 network_monitor.py

# Executar com privilégios (RECOMENDADO)
# Linux/macOS:
sudo python3 network_monitor.py

# Windows (PowerShell como Administrador):
python network_monitor.py
```

---

## 🎮 Guia de Uso Completo

### 🔑 Teclas Principais

#### Navegação de Views
- **1** - View de Conexões
- **2** - View de Processos (com ordenação)
- **3** - View de Tráfego (com gráficos)
- **4** - View de Alertas
- **5** - View de Estatísticas

#### Controles Gerais
- **Q** - Sair do programa
- **R** - Forçar atualização imediata
- **/** - Ativar modo de busca
- **ESC** - Sair do modo de busca

#### Navegação e Scroll
- **↑/↓** - Navegar item por item
- **Page Up/Down** - Scroll rápido (10 itens)
- **Home** - Ir para o início
- **End** - Ir para o final

#### Exportação
- **E** - Exportar para JSON
- **C** - Exportar para CSV (exceto na view de processos)

#### Filtros (View de Conexões)
- **F** - Filtrar apenas conexões externas
- **S** - Filtrar apenas conexões estabelecidas

#### Ordenação (View de Processos)
- **C** - Ordenar por número de Conexões
- **U** - Ordenar por uso de CPU
- **M** - Ordenar por uso de Memória
- **N** - Ordenar por Nome do processo
- *(Pressionar novamente inverte a ordem)*

---

## 🔍 Sistema de Busca

### Como Usar:
1. Pressione **/** em qualquer view
2. Digite o termo de busca
3. Pressione **Enter** para confirmar ou **ESC** para cancelar

### O que pode ser buscado:

**View de Conexões:**
- Endereços IP (local ou remoto)
- Portas
- Nome do processo
- PID
- Hostname (após DNS reverso)

**View de Processos:**
- Nome do processo
- PID
- Caminho do executável

**Exemplos:**
- `192.168` - Encontra todas conexões na rede local
- `chrome` - Encontra todas conexões do Chrome
- `443` - Encontra conexões HTTPS
- `google.com` - Encontra por hostname

---

## 📊 Interpretando os Gráficos ASCII

### View de Tráfego - Gráficos de Barras

```
eth0                 ↓ 2.3 MB/s  ↑ 450 KB/s
    ████    ██      
    ████  ████      
    ████  ████  ██  
    ████████████████
```

- **Altura** = Intensidade do tráfego
- **Largura** = Últimos 60 segundos
- **Verde** = Tráfego de recebimento (↓)
- **Amarelo** = Tráfego de envio (↑)

### View de Processos - Sparklines

```
PID      PROCESSO     SPARK
1234     chrome       ▁▂▃▄▅▆▇█▇▆▅
```

- Caracteres: ` ▁▂▃▄▅▆▇█`
- Representa tráfego total (recv + sent)
- Últimos ~14 segundos
- Quanto mais alto o caractere, maior o tráfego

---

## 🎯 Views Detalhadas

### 1️⃣ View de Conexões

**O que mostra:**
- Tipo de protocolo (TCP/UDP)
- Endereços local e remoto
- Estado da conexão
- PID e processo
- Hostname (DNS reverso)
- Localização geográfica

**Cores:**
- 🔴 **Vermelho** = Conexão suspeita
- 🟡 **Amarelo** = Externa estabelecida
- 🟣 **Magenta** = Externa não estabelecida
- 🟢 **Verde** = Conexão local
- 🔵 **Azul** (fundo) = Item selecionado

**Detalhes da Seleção:**
Mostra na parte inferior:
- IP remoto completo
- Hostname (se disponível)
- Razões de suspeita
- Caminho do executável

**Exemplo de uso:**
1. Pressione **F** para ver apenas conexões externas
2. Pressione **S** para ver apenas estabelecidas
3. Use **/** para buscar por domínio específico
4. Navegue com **↑↓** para ver detalhes

### 2️⃣ View de Processos

**O que mostra:**
- PID do processo
- Nome do processo
- Uso de CPU (%)
- Uso de memória (MB)
- Número de conexões ativas
- Largura de banda (↓/↑)
- Sparkline de tráfego

**Ordenação:**
- **C** = Por conexões (padrão, útil para ver processos com muita atividade de rede)
- **U** = Por CPU (útil para ver impacto no processador)
- **M** = Por memória (útil para ver uso de RAM)
- **N** = Por nome (ordem alfabética)

**Indicadores:**
- `⇅` = Coluna não ordenada
- `↓` = Ordem decrescente
- `↑` = Ordem crescente

**Exemplo de uso:**
1. Pressione **U** para ordenar por CPU
2. Veja quais processos estão consumindo mais
3. Pressione **/** e busque por nome
4. Use sparklines para ver padrão de tráfego

### 3️⃣ View de Tráfego

**O que mostra:**
- Estatísticas gerais de rede
- Gráficos ASCII em tempo real
- Tráfego por interface
- Pacotes enviados/recebidos
- Erros e drops

**Gráficos:**
- Mostra últimos 60 segundos
- Atualiza a cada 2 segundos
- Separado por interface (eth0, wlan0, etc.)
- Duas cores: verde (recv) e amarelo (sent)

**Exemplo de uso:**
1. Monitore o gráfico durante download
2. Veja qual interface está mais ativa
3. Identifique picos de tráfego

### 4️⃣ View de Alertas

**O que mostra:**
- Todos os alertas de segurança
- Timestamp de cada alerta
- Nível de severidade

**Níveis:**
- 🟢 **Info** = Informativo
- 🟡 **Warning** = Aviso
- 🔴 **Critical** = Crítico

**Tipos de alertas:**
- Port scans detectados
- Alto uso de banda
- Processos com muitas conexões
- Conexões suspeitas
- Problemas de permissão

### 5️⃣ View de Estatísticas

**O que mostra:**
- Resumo geral do monitoramento
- Contadores globais
- Cache de DNS e Geo
- Avisos de permissão

---

## 🛡️ Sobre Permissões

### Por que preciso de Administrador/root?

O sistema operacional restringe o acesso a informações de rede por segurança. Sem privilégios elevados:

❌ **Não funciona:**
- Ver conexões de outros usuários
- Ver processos de sistema
- Acessar PIDs de alguns processos

✅ **Funciona:**
- Ver suas próprias conexões
- Estatísticas gerais de rede
- Tráfego por interface

### Como executar com privilégios:

**Linux/macOS:**
```bash
sudo python3 network_monitor.py
```

**Windows:**
1. Abrir PowerShell como Administrador
2. Navegar até a pasta do script
3. Executar: `python network_monitor_v2.py`

### Detectando Problemas de Permissão:

O monitor detecta e avisa automaticamente:
- ⚠️ Alerta no início se não tiver privilégios
- 🔢 Contador de processos sem acesso
- 📊 Estatística de "Access Denied"

---

## 🚀 Casos de Uso Práticos

### 1. Investigar Alto Uso de Rede
```
1. View de Processos (tecla 2)
2. Ordenar por conexões (tecla C)
3. Ver quais processos têm mais conexões
4. Verificar sparkline de tráfego
5. Ir para View de Tráfego (tecla 3) para ver gráfico detalhado
```

### 2. Encontrar Conexões de um Programa
```
1. View de Conexões (tecla 1)
2. Pressionar / para buscar
3. Digitar nome do programa (ex: "chrome")
4. Enter para confirmar
5. Ver todas conexões filtradas
```

### 3. Monitorar Segurança
```
1. View de Alertas (tecla 4)
2. Verificar alertas críticos em vermelho
3. Se houver port scan, ver IP suspeito
4. Ir para View de Conexões
5. Filtrar por externas (tecla F)
6. Buscar IP suspeito (tecla /)
```

### 4. Análise Forense
```
1. View de Conexões com filtros
2. Exportar para JSON (tecla E)
3. Arquivo salvo em network_monitor_export.json
4. Analisar dados offline ou compartilhar
```

### 5. Troubleshooting de Rede
```
1. View de Tráfego (tecla 3)
2. Ver gráficos de cada interface
3. Identificar picos ou quedas
4. Verificar erros e drops
5. Correlacionar com problemas reportados
```

---

## 📈 Melhorias da Versão 2.0 vs 1.0

| Funcionalidade | v1.0 | v2.0 |
|----------------|------|------|
| **Scroll** | ❌ Limitado | ✅ Ilimitado com indicadores |
| **DNS Reverso** | ❌ Não | ✅ Assíncrono com cache |
| **Ordenação** | ❌ Fixa | ✅ 4 critérios dinâmicos |
| **Busca** | ❌ Não | ✅ Busca em tempo real |
| **Gráficos** | ❌ Não | ✅ Barras e sparklines |
| **Erros de Permissão** | ⚠️ Básico | ✅ Tratamento robusto |
| **Navegação** | ⚠️ Básica | ✅ Completa (PgUp/Dn/Home/End) |
| **Performance** | ✅ Boa | ✅ Excelente (threads) |

---

## 🔧 Configurações Avançadas

Edite o código para ajustar:

```python
self.config = {
    'update_interval': 2,  # Intervalo de atualização (segundos)
    'alert_threshold_connections': 50,  # Alerta se > 50 conexões
    'alert_threshold_bandwidth': 10 * 1024 * 1024,  # 10 MB/s
    'suspicious_ports': [4444, 5555, 6666, 31337, 12345],
    'enable_geo_lookup': True,  # Ativar geolocalização
    'max_geo_requests': 10,  # Limite de requests de geo
    'enable_dns_reverse': True  # Ativar DNS reverso
}
```

**Cache DNS:**
```python
DNSResolver(cache_size=100)  # Ajustar tamanho do cache
```

**Histórico de tráfego:**
```python
deque(maxlen=60)  # 60 segundos de histórico
```

---

## 🐛 Troubleshooting

### Problema: "Permission Denied" no Linux
**Solução:**
```bash
sudo python3 network_monitor.py
```

### Problema: "Access Denied" no Windows
**Solução:**
1. Fechar o programa
2. Clicar com botão direito no PowerShell
3. "Executar como Administrador"
4. Executar novamente

### Problema: Terminal muito pequeno
**Solução:**
Redimensionar para pelo menos 120x35 caracteres

### Problema: Gráficos não aparecem
**Solução:**
- Verificar se há dados (aguardar alguns segundos)
- Ir para View de Tráfego (tecla 3)
- Verificar se interfaces têm tráfego

### Problema: DNS reverso não funciona
**Solução:**
- Verificar conexão com internet
- Aguardar alguns segundos (é assíncrono)
- Alguns IPs podem não ter hostname

### Problema: Busca não encontra nada
**Solução:**
- Verificar se digitou corretamente
- Busca é case-insensitive
- Pressionar Enter para confirmar
- ESC para limpar e tentar novamente

---

## 📊 Interpretando Alertas de Segurança

### ⚠️ "Possível port scan detectado"
- Indica que um IP fez muitas conexões em pouco tempo
- Pode ser malicioso ou legítimo (ex: CDN, load balancer)
- **Ação:** Verificar IP, país de origem, bloquear se suspeito

### ⚠️ "Alto tráfego de saída"
- Processo enviando > 10 MB/s
- Normal para uploads, backups, streaming
- **Ação:** Verificar se é esperado

### ⚠️ "Muitas conexões"
- Processo com > 50 conexões simultâneas
- Normal para servidores, browsers
- **Ação:** Verificar se é esperado

### ⚠️ "Porta suspeita"
- Conexão em porta conhecida de backdoor
- Portas: 4444, 5555, 6666, 31337, 12345
- **Ação:** Investigar processo imediatamente

### 🔴 "PERMISSÃO NEGADA"
- Programa não tem acesso administrativo
- **Ação:** Executar como admin/root

---

## 💡 Dicas de Performance

1. **Intervalo de Atualização:**
   - Padrão: 2 segundos
   - Para menos CPU: aumentar para 5s
   - Para mais responsividade: diminuir para 1s

2. **Cache DNS:**
   - Padrão: 100 entradas
   - Aumentar se tiver muitos IPs únicos
   - Diminuir se quiser economizar RAM

3. **Histórico:**
   - Padrão: 60 segundos
   - Aumentar para ver tendências maiores
   - Diminuir para economizar RAM

4. **Geo-localização:**
   - Limitar requests se internet lenta
   - Desativar se não for necessário

---

## 🆚 Comparação com Outras Ferramentas

| Ferramenta | Plataforma | GUI | Gráficos | DNS | Busca | Export |
|------------|-----------|-----|----------|-----|-------|--------|
| **NetMonitor v2** | Multi | TUI | ✅ | ✅ | ✅ | ✅ |
| netstat | Multi | CLI | ❌ | ❌ | ❌ | ❌ |
| tcpview (Windows) | Windows | GUI | ❌ | ✅ | ⚠️ | ❌ |
| iftop | Linux | TUI | ⚠️ | ✅ | ❌ | ❌ |
| nethogs | Linux | TUI | ❌ | ❌ | ❌ | ❌ |
| Wireshark | Multi | GUI | ✅ | ✅ | ✅ | ✅ |

**Vantagens do NetMonitor v2:**
- ✅ Leve e rápido
- ✅ Não precisa instalação complexa
- ✅ Interface intuitiva
- ✅ Gráficos ASCII (funciona via SSH)
- ✅ Busca e filtros poderosos
- ✅ Export fácil para análise

---

## 🔮 Roadmap Futuro

- [ ] Suporte a IPv6
- [ ] Filtragem por porta
- [ ] Bloqueio de IPs integrado
- [ ] Temas de cores
- [ ] Modo compacto
- [ ] Logs persistentes
- [ ] Integração com VirusTotal
- [ ] Gráficos com cores ANSI 256
- [ ] Dashboard web opcional

---

## 📝 Licença

Código fornecido como exemplo educacional.

## 🤝 Contribuindo

Sugestões e melhorias são bem-vindas!

---

**Desenvolvido com ❤️ e Python** 🐍

*Monitor de Rede v2.0 - Todas as funcionalidades solicitadas implementadas!*
