# Tech Challenge - Fase 5 - Hackaton

## Modelagem de Ameaças utilizando IA

**Instituição**: FIAP - Pós Tech
**Disciplina**: Software Security
**Fase**: 5 - Hackaton

---

## 1. Contexto do Problema

A FIAP Software Security está analisando a viabilidade de uma nova funcionalidade para otimizar seu software de análise de vulnerabilidades em arquitetura de sistemas. O desafio é utilizar Inteligência Artificial para realizar automaticamente a modelagem de ameaças, baseado na metodologia STRIDE, a partir de um diagrama de arquitetura de software em imagem.

O objetivo é desenvolver um MVP para detecção de ameaças que:
- Interprete automaticamente um diagrama de arquitetura de sistema
- Identifique os componentes (usuários, servidores, bases de dados, APIs, etc.)
- Analise a topologia (grupos, conexões, fluxo de dados)
- Gere um Relatório de Modelagem de Ameaças baseado na metodologia STRIDE
- Busque vulnerabilidades relacionadas a cada componente e contramedidas específicas

---

## 2. Metodologia STRIDE

A metodologia STRIDE classifica ameaças em 6 categorias:

| Categoria | Significado | Descrição |
|-----------|-------------|-----------|
| **S** - Spoofing | Falsificação de identidade | Atacante finge ser outro usuário ou sistema |
| **T** - Tampering | Adulteração de dados | Modificação não autorizada de dados em trânsito ou repouso |
| **R** - Repudiation | Negação de ações | Ausência de rastreabilidade permite negar ações realizadas |
| **I** - Information Disclosure | Vazamento de informações | Exposição de dados sensíveis a partes não autorizadas |
| **D** - Denial of Service | Negação de serviço | Tornar o sistema indisponível para usuários legítimos |
| **E** - Elevation of Privilege | Elevação de privilégio | Obter permissões acima do autorizado |

---

## 3. Arquitetura da Solução

### 3.1 Pipeline com Claude API (Notebooks 01, 02 e 03)

Os notebooks 01 e 02 executam o pipeline em etapas separadas (detecção e análise STRIDE, respectivamente). O notebook 03 consolida todo o pipeline end-to-end em um único notebook.

```
Imagem de Arquitetura (.png)
        |
  [Passo 1] Identificar provedor cloud — Claude Vision API
        |
  [Passo 2a] Detectar componentes visuais — Florence-2 (local)
        |
  [Passo 2b] Classificar componentes — Claude Vision API
        |
  [Passo 2c] Analisar topologia — Claude Vision API
        |
  [Passo 3] Análise STRIDE por componente — Claude API
        |
  [Passo 4] Relatório de Ameaças (JSON + HTML)
```

### 3.2 Pipeline Local (Notebook 04)

O notebook 04 executa o mesmo pipeline, substituindo todas as chamadas ao Claude API pelo modelo open-source **Qwen2.5-VL-72B-Instruct-AWQ** rodando localmente na GPU. Custo de API = US$ 0,00.

```
Imagem de Arquitetura (.png)
        |
  [Passo 1] Identificar provedor cloud — Qwen2.5-VL-72B (local)
        |
  [Passo 2a] Detectar componentes visuais — Florence-2 (local)
        |
  [Passo 2b] Classificar componentes — Qwen2.5-VL-72B (local)
        |
  [Passo 2c] Analisar topologia — Qwen2.5-VL-72B (local)
        |
  [Passo 3] Análise STRIDE por componente — Qwen2.5-VL-72B (local)
        |
  [Passo 4] Relatório de Ameaças (JSON + HTML)
```

> Requer GPU A100 com alta memória (80 GB) — VRAM mínima ~42 GB.

### 3.3 Detalhamento dos Passos

#### Passo 1 - Identificação do Provedor Cloud

O sistema recebe uma imagem de diagrama de arquitetura e identifica automaticamente se pertence à AWS, Azure ou GCP. Isso é feito via análise visual de:
- Logotipos e ícones característicos de cada provedor
- Paleta de cores (laranja/amarelo para AWS, azul para Azure, azul/verde/vermelho para GCP)
- Nomenclatura dos serviços presentes na imagem

**Modelo utilizado**: Claude Vision API (multimodal)
**Input**: Imagem PNG do diagrama
**Output**: String identificando o provedor (`"AWS"`, `"Azure"` ou `"GCP"`)

#### Passo 2a - Detecção Visual de Componentes

**Florence-2-large-ft** (Microsoft, pré-treinado fine-tuned):
- Modelo de visão computacional com 770M de parâmetros (versão fine-tuned para melhor detecção)
- Realiza detecção zero-shot com 5 estratégias complementares:
  - `OCR_WITH_REGION`: detecta textos (nomes dos serviços) com bounding boxes
  - `CAPTION_TO_PHRASE_GROUNDING`: localiza termos específicos de componentes cloud (1 serviço por query)
  - `REGION_PROPOSAL`: propostas genéricas de regiões de interesse
  - `DENSE_REGION_CAPTION`: regiões com legenda densa
  - `OD`: detecção de objetos (complementar)
- Tiling 3x3 com 20% de overlap: repete todas as estratégias em cada tile para capturar componentes menores
- Filtros para diagramas técnicos (min_area_ratio=0.0005, max_area_ratio=0.03, min_size=5px)
- NMS (Non-Maximum Suppression) com IoU > 0.5 para remover duplicatas

**Input**: Imagem PNG do diagrama
**Output**: Lista de bounding boxes com labels brutos

#### Passo 2b - Classificação de Componentes

**Claude Vision API** (classificação refinada):
- Recebe os recortes (crops) de cada bounding box detectado pelo Florence-2
- Classifica cada componente com nome específico do serviço cloud
- Deduplicação espacial pós-classificação: agrupa por nome, clusteriza por proximidade (centros < 100px), mantém menor bbox por cluster

**Input**: Crops dos bounding boxes + imagem completa para contexto
**Output**: Lista de componentes detectados com:
- Nome do serviço (ex: "Amazon RDS", "API Gateway")
- Classe genérica (ex: "database", "api_gateway")
- Bounding box (coordenadas x, y, largura, altura)
- Provedor cloud (AWS / Azure / GCP)

#### Passo 2c - Análise de Topologia

**Claude Vision API** (análise topológica):
- Recebe a imagem completa + lista de componentes detectados
- Identifica a estrutura organizacional do diagrama:
  - **Grupos/containers**: VPC, Subnets, Availability Zones, Resource Groups
  - **Conexões**: setas e linhas entre componentes (comunicação, dependência)
  - **Fluxo de dados**: ordem do tráfego de ponta a ponta (do usuário ao backend)

**Input**: Imagem PNG + lista de componentes
**Output**: JSON com `groups`, `connections` e `data_flow`

#### Passo 3 - Análise STRIDE

Para cada componente detectado, o Claude API gera uma análise STRIDE completa com contexto topológico:

**Input**: Componente + lista completa de componentes + provedor + topologia (grupo, conexões, posição no fluxo)
**Output**: Para cada componente:
- Ameaças identificadas por categoria STRIDE (S/T/R/I/D/E)
- Nível de risco (Alto / Médio / Baixo)
- Contramedidas recomendadas para cada ameaça
- Referências a boas práticas do provedor (AWS Well-Architected / Azure Security Benchmark / Google Cloud Architecture Framework)

**Parser robusto**: 3 estratégias de fallback (clean+parse, raw extract, regex per-category) para garantir extração do JSON mesmo com variações na resposta do modelo.

#### Passo 4 - Geração do Relatório

O sistema consolida toda a análise em dois formatos:

**JSON estruturado**: Para integração com outros sistemas
```json
{
  "metadata": { "project": "...", "methodology": "STRIDE", "provider": "AWS" },
  "topology": { "groups": [...], "connections": [...], "data_flow": [...] },
  "components": [
    {
      "name": "Amazon RDS (Primary)",
      "class": "database",
      "bbox": [184, 462, 112, 75],
      "threats": {
        "spoofing": {
          "threat": "Acesso não autenticado ao banco de dados",
          "risk": "Alto",
          "countermeasure": "Habilitar IAM Database Authentication",
          "reference": "AWS Well-Architected - SEC05"
        }
      }
    }
  ],
  "summary": { "total_components": 15, "total_threats": 90, "risk_distribution": {...} }
}
```

**HTML formatado**: Para apresentação e documentação, contendo:
- Resumo executivo com badges coloridas de risco (Alto=vermelho, Médio=amarelo, Baixo=verde)
- Imagens da arquitetura embutidas em base64 (original + anotada com bboxes numerados)
- Seção de topologia: fluxo de dados visual com chips, grupos/containers hierárquicos, tabela de conexões
- Tabela de componentes com numeração (#N), classe, localização topológica e provedor
- Nota explicativa quando há componentes com mesmo nome em diferentes zonas de disponibilidade
- Análise STRIDE detalhada por componente: badge de localização, chips de conexões, 6 categorias com nível de risco
- CSS inline (sem dependências externas), pode ser salvo como PDF pelo navegador (Ctrl+P)

---

## 4. Classes de Detecção

### 4.1 Categorias de Componentes

```python
CLASSES = {
    # Rede e Segurança
    'waf_firewall':      ['AWS WAF', 'AWS Shield', 'Azure Firewall', 'Cloud Armor'],
    'cdn':               ['Amazon CloudFront', 'Azure CDN', 'Cloud CDN'],
    'load_balancer':     ['ALB', 'NLB', 'Azure Load Balancer', 'Cloud Load Balancing'],
    'vpc_vnet':          ['VPC', 'VNet', 'Subnet', 'VPC Network'],

    # Computação
    'compute':           ['EC2', 'SEI/SIP', 'App Service', 'VM', 'Compute Engine', 'GKE', 'App Engine'],
    'auto_scaling':      ['Auto Scaling Group', 'VMSS', 'Instance Groups', 'Autoscaler'],
    'orchestrator':      ['Logic Apps', 'Step Functions', 'Lambda', 'Cloud Functions', 'Cloud Workflows'],

    # Dados
    'database':          ['RDS', 'Aurora', 'Azure SQL', 'Cosmos DB', 'Cloud SQL', 'Firestore', 'Spanner'],
    'cache':             ['ElastiCache', 'Azure Cache for Redis', 'Memorystore'],
    'storage':           ['S3', 'EFS', 'Azure Blob', 'NFS', 'Cloud Storage', 'Filestore'],

    # API e Integração
    'api_gateway':       ['API Gateway', 'Azure API Management', 'Apigee', 'Extensible Service Proxy'],
    'developer_portal':  ['Developer Portal', 'API Portal'],
    'web_service':       ['REST', 'SOAP', 'SaaS Service', 'Cloud Run'],

    # Identidade e Segurança
    'auth_identity':     ['IAM', 'Microsoft Entra', 'Cognito', 'Cloud IAM', 'Identity Platform'],
    'kms_encryption':    ['AWS KMS', 'Azure Key Vault', 'Cloud KMS'],

    # Observabilidade
    'monitoring':        ['CloudWatch', 'CloudTrail', 'Azure Monitor', 'Cloud Monitoring', 'Cloud Logging', 'Cloud Audit Logs'],
    'backup':            ['AWS Backup', 'Azure Backup', 'Backup and DR'],

    # Mensageria
    'messaging':         ['SES', 'SQS', 'SNS', 'Azure Service Bus', 'Pub/Sub', 'Cloud Tasks'],

    # Atores
    'user_actor':        ['Usuário', 'Developer', 'Client'],
}
```

### 4.2 Exemplos de Mapeamento STRIDE por Componente

| Componente | S (Spoofing) | T (Tampering) | R (Repudiation) | I (Info Disclosure) | D (DoS) | E (Elevation) |
|-----------|--------------|---------------|-----------------|---------------------|---------|----------------|
| API Gateway (Azure) | Token forjado no header | Request tampering sem validação | Sem logging de requests | Logs do gateway expostos | Sem rate limiting | Bypass de authorization |
| RDS Primary/Secondary | Credenciais comprometidas | SQL Injection | Sem audit logs habilitados | Dados sem encryption at rest | Sem Multi-AZ failover | Conta admin compartilhada |
| CloudFront + WAF | Bypass do WAF via IP direto | Cache poisoning | Sem access logs | Headers sensíveis expostos | DDoS sem rate limiting | Regras WAF permissivas |
| Microsoft Entra | Credential stuffing | Token tampering | Sem MFA logging | Tokens com claims excessivos | Account lockout abuse | Roles mal configuradas |
| Load Balancer (ALB) | IP spoofing | Header injection | Sem connection logging | Health check info leak | Slowloris attack | Target group misconfiguration |
| ElastiCache | Acesso não autenticado | Data corruption em cache | Sem audit trail | Dados sensíveis em cache sem TLS | Memory exhaustion | Acesso ao cluster sem RBAC |

---

## 5. Arquiteturas de Teste

O sistema será avaliado com três arquiteturas de referência:

### 5.1 Arquitetura 1 - AWS

**Arquivo**: `imagens/arquitetura 1.png`

Componentes presentes:
- **Camada externa**: Usuários SEI, AWS Shield, Amazon CloudFront, AWS WAF
- **AWS Cloud > Region São Paulo > VPC**:
  - 3 Availability Zones (A, B, C)
  - Cada AZ possui:
    - Public Subnet: Application Load Balancer
    - Private Subnet: Auto Scaling com servidores SEI/SIP
    - Private Subnet: Armazenamento (EFS, RDS, ElastiCache, Solr)
  - Específicos por AZ:
    - AZ A: Amazon Elastic File System (NFS) Multi-AZ + Amazon RDS (Primary)
    - AZ B: Amazon RDS (Secondary) + Amazon ElastiCache (Multiaz)
    - AZ C: Solr com Auto Scaling
- **Serviços auxiliares** (fora da VPC, dentro da Cloud):
  - AWS CloudTrail (auditoria)
  - AWS Key Management Service (criptografia)
  - AWS Backup (backup)
  - Amazon CloudWatch (monitoramento)
  - Amazon Simple Email Service - SES (email)

### 5.2 Arquitetura 2 - Azure

**Arquivo**: `imagens/arquitetura 2.png`

Componentes presentes:
- **Atores externos**:
  - Usuário (acesso HTTP, autenticação)
  - Developer (cria aplicação, consome documentação API)
- **Microsoft Entra**: Serviço de autenticação/identidade
- **API Management** (Resource Group):
  - API Gateway (ponto de entrada, publica interfaces)
  - Developer Portal (documentação de APIs)
  - Logic Apps (workflow e orquestração)
- **Backend Systems**:
  - Azure Services
  - SaaS Services
  - Web Services (REST, SOAP)
- **Fluxo numerado**: 1 (User HTTP) → 2 (Entra Auth) → 3 (API Gateway) → 4 (Logic Apps) → 5 (Backend Systems)

### 5.3 Arquitetura 3 - GCP

**Arquivo**: `imagens/arquitetura 3.png`

Componentes presentes:
- **Clientes externos**: Android, Chrome, iOS, Other
- **Cloud Load Balancing**: Balanceamento de carga na entrada
- **ESP Container**: Extensible Service Proxy (autenticação e controle de API)
- **API Container**: Backend da aplicação
- **Gerenciamento de serviços**:
  - gcloud → Service Management → ESP
  - Service Control → Cloud Console
- **Fluxo**: Clients → Cloud Load Balancing → ESP Container → API Container

---

## 6. Stack Tecnológica

### 6.1 Ambiente de Desenvolvimento

| Item | Tecnologia |
|------|-----------|
| **Ambiente** | Google Colab Pro (GPU T4/A100) |
| **Linguagem** | Python 3.11 |
| **Storage** | Google Drive |
| **Versionamento** | GitHub |

### 6.2 Bibliotecas Principais

| Biblioteca | Uso |
|-----------|-----|
| `transformers` | Florence-2 (detecção de componentes) |
| `anthropic` | Claude API — classificação, topologia, STRIDE (notebooks 01-03) |
| `autoawq` | Quantização AWQ para Qwen2.5-VL-72B (notebook 04) |
| `qwen-vl-utils` | Processamento de imagens para Qwen2.5-VL (notebook 04) |
| `supervision` | Visualização de bounding boxes numerados |
| `timm` | Dependência do Florence-2 (modelos de visão) |
| `einops` | Dependência do Florence-2 (operações tensoriais) |
| `torch` | Backend para Florence-2 (pré-instalado no Colab) |
| `Pillow` | Manipulação de imagens (pré-instalado no Colab) |
| `matplotlib` | Visualizações (pré-instalado no Colab) |

> **Nota sobre `flash_attn`**: A biblioteca Flash Attention (`flash_attn`) seria utilizada para acelerar o mecanismo de atenção do Florence-2, reduzindo o consumo de memória GPU e aumentando a velocidade de inferência. Porém, a compilação falha no ambiente Google Colab devido a incompatibilidades com a versão do CUDA/compilador disponível. O Florence-2 funciona normalmente sem ela, utilizando a implementação padrão de atenção do PyTorch.

### 6.3 Modelos de IA

| Modelo | Provedor | Parâmetros | Uso no Projeto |
|--------|----------|-----------|----------------|
| **Florence-2-large-ft** | Microsoft | 770M | Detecção zero-shot de componentes visuais (bounding boxes) |
| **Claude Sonnet 4.6** | Anthropic | — | Identificação de provedor, classificação, topologia, STRIDE (notebooks 01-03) |
| **Qwen2.5-VL-72B-Instruct-AWQ** | Alibaba/Qwen | 72B (4-bit) | Substituto local do Claude API no notebook 04 (~40 GB VRAM) |

### 6.4 Estimativa de Custo por Imagem Analisada

Preços base do Claude Sonnet 4.6: **$3.00 / 1M tokens de input** e **$15.00 / 1M tokens de output**.

| Etapa | Chamadas API | Tokens Input | Tokens Output | Custo Input | Custo Output | Subtotal (USD) | Subtotal (BRL) |
|-------|-------------|-------------|--------------|-------------|-------------|---------------|---------------|
| Passo 1 — Identificar provedor | 1 | ~1.800 | ~50 | $0,005 | $0,001 | **$0,006** | **R$ 0,03** |
| Passo 2b — Classificação | ~15 | ~15.000 | ~2.500 | $0,045 | $0,038 | **$0,083** | **R$ 0,46** |
| Passo 2c — Topologia | 1 | ~2.500 | ~2.000 | $0,008 | $0,030 | **$0,038** | **R$ 0,21** |
| Passo 3 — Análise STRIDE | ~15 | ~52.500 | ~7.500 | $0,158 | $0,113 | **$0,271** | **R$ 1,49** |
| **Total por imagem** | **~32** | **~71.800** | **~12.050** | **$0,216** | **$0,182** | **~$0,40** | **~R$ 2,19** |

> **Custo estimado por imagem analisada: ~US$ 0,40 (~R$ 2,19)**
> Cotação utilizada: US$ 1,00 = R$ 5,50
>
> Florence-2 roda localmente na GPU do Colab (sem custo adicional de API).
> Google Colab Pro: ~US$ 10/mês (~R$ 55/mês) — inclui acesso a GPU T4/A100.

---

## 7. Estrutura do Projeto

### 7.1 Repositório GitHub

```
Tech-Challenge---Fase-5-Hackaton/
├── README.md                          # Este arquivo
├── prompt.txt                         # Contexto completo para recriar o projeto
├── IADT - Fase 5 - Hackaton.pdf       # Enunciado do projeto
├── imagens/
│   ├── arquitetura 1.png              # Diagrama AWS (teste)
│   ├── arquitetura 2.png              # Diagrama Azure (teste)
│   └── arquitetura 3.png              # Diagrama GCP (teste)
├── notebooks/
│   ├── 01_component_detection.ipynb   # Detecção de componentes + topologia
│   ├── 02_stride_analysis.ipynb       # Análise STRIDE + relatório
│   ├── 03_consolidado.ipynb           # Pipeline consolidado end-to-end (Claude API)
│   └── 04_local_pipeline.ipynb        # Pipeline 100% local (sem API, Qwen2.5-VL)
└── outputs/
    ├── detections/                    # JSONs + imagens anotadas com bboxes
    └── reports/                       # Relatórios STRIDE (JSON + HTML)
```

### 7.2 Google Drive

```
MyDrive/
└── hackaton-stride/
    ├── test_images/                   # Imagens de teste (arquitetura 1, 2 e 3)
    └── outputs/
        ├── detections/                # Resultados da detecção + imagens anotadas
        └── reports/                   # Relatórios gerados (JSON + HTML)
```

> Os notebooks criam automaticamente todas as pastas necessárias no Google Drive na primeira execução.

---

## 8. Notebooks

### Requisitos de Hardware

| Notebook | GPU | VRAM Mínima | API Key | Observações |
|----------|-----|-------------|---------|-------------|
| **01** - Detecção de Componentes | T4 ou A100 | ~4 GB | Anthropic | Florence-2 (~1.5 GB) + Claude API |
| **02** - Análise STRIDE | CPU suficiente | — | Anthropic | Apenas chamadas API, sem modelo local |
| **03** - Pipeline Consolidado | T4 ou A100 | ~4 GB | Anthropic | Florence-2 + Claude API |
| **04** - Pipeline Local | **A100 80 GB** | **~42 GB** | Nenhuma | Florence-2 (~1.5 GB) + Qwen2.5-VL-72B-AWQ (~40 GB) |

### Configuração Necessária

Antes de executar qualquer notebook no Google Colab:

1. **Secrets** (notebooks 01, 02 e 03): No menu lateral do Colab, clique em 🔑 **Secrets** e adicione:
   - `ANTHROPIC_API_KEY`: Chave de API da Anthropic (obtenha em https://console.anthropic.com)
   - O notebook 04 **não** requer chave de API.

2. **Ambiente de execução**: No menu **Ambiente de execução > Alterar tipo de ambiente de execução**:
   - **Notebooks 01 e 03**: Selecione **GPU T4** (gratuita) ou **A100** (Colab Pro) — necessário para Florence-2
   - **Notebook 02**: **CPU** é suficiente (apenas chamadas API). Funciona também com GPU, mas não é necessário.
   - **Notebook 04**: Selecione **GPU A100 com alta memória (80 GB)** (Colab Pro) — nos testes foi necessário ao menos 42 GB de VRAM para carregar o Qwen2.5-VL-72B-AWQ

> Os notebooks 03 e 04 detectam automaticamente as imagens disponíveis na pasta `test_images/` do Google Drive (padrão `arquitetura *.png`) e processam todas elas, sem necessidade de ajustar o código para adicionar ou remover imagens.

### 8.1 Notebook 01 - Detecção de Componentes (`01_component_detection.ipynb`)

**GPU necessária**: T4 ou A100 | **VRAM**: ~4 GB

**Etapas**:
1. Montar Google Drive e carregar imagem de teste
2. **Passo 1 - Identificar provedor**: Enviar imagem ao Claude Vision API com prompt para identificar se é AWS, Azure ou GCP
3. **Passo 2a - Detecção visual**: Carregar Florence-2 (`microsoft/Florence-2-large-ft`) e executar detecção com 5 estratégias (OCR, Phrase Grounding, Region Proposal, Dense Caption, OD) na imagem completa + tiling 3x3 com 20% overlap
4. **Passo 2b - Classificação**: Recortar cada região detectada (crop dos bounding boxes) e enviar ao Claude Vision para classificação refinada com nome exato do serviço. Deduplicação espacial por proximidade (centros < 100px).
5. **Passo 2c - Topologia**: Enviar imagem completa + lista de componentes ao Claude Vision para identificar grupos (VPC, Subnets, AZs), conexões entre componentes e fluxo de dados end-to-end
6. Salvar resultados em JSON (componentes com bboxes, classes e topologia)
7. Visualizar imagem com bounding boxes numerados (#N) usando `supervision`

**Output**:
- `outputs/detections/componentes_arquitetura_X.json`
- `outputs/detections/annotated_arquitetura_X.png`

### 8.2 Notebook 02 - Análise STRIDE (`02_stride_analysis.ipynb`)

**GPU necessária**: Nenhuma (CPU suficiente) | **VRAM**: —

**Etapas**:
1. Carregar JSON de componentes detectados (inclui topologia)
2. Para cada componente, montar prompt STRIDE contextualizado:
   - Nome, classe e provedor do componente
   - Posição topológica: grupo/container, conexões, posição no fluxo de dados
   - Contexto completo da arquitetura (outros componentes presentes)
3. Enviar ao Claude API para análise STRIDE completa (parser robusto com 3 fallbacks)
4. Para cada ameaça, gerar contramedidas específicas do provedor
5. Consolidar em JSON estruturado
6. Gerar relatório HTML com:
   - Imagens embutidas em base64 (original + anotada)
   - Seção de topologia (fluxo visual, grupos, conexões)
   - Tabela de componentes com localização topológica
   - Análise STRIDE detalhada com badges de risco e conexões

**Output**:
- `outputs/reports/stride_arquitetura_X.json`
- `outputs/reports/stride_arquitetura_X.html`

### 8.3 Notebook 03 - Pipeline Consolidado (`03_consolidado.ipynb`)

**GPU necessária**: T4 ou A100 | **VRAM**: ~4 GB

**Etapas**:
1. Pipeline end-to-end: recebe imagem → identifica provedor → detecta componentes → analisa topologia → analisa STRIDE → gera relatório
2. Detecta automaticamente as imagens disponíveis na pasta do Google Drive e processa todas
3. Visualização com bounding boxes numerados (#N) + resumo do relatório
4. Métricas de execução: tempo de processamento por etapa, número de componentes detectados, número de ameaças identificadas
5. Estimativa de custo por imagem (Claude API + Colab GPU)

**Output**: Relatórios completos para cada arquitetura (JSON + HTML + imagens anotadas)

### 8.4 Notebook 04 - Pipeline Local (`04_local_pipeline.ipynb`)

**GPU necessária**: A100 80 GB (Colab Pro) | **VRAM**: ~42 GB

Pipeline 100% local que substitui todas as chamadas ao Claude API por **Qwen2.5-VL-72B-Instruct-AWQ** (modelo open-source). Custo de API = **US$ 0,00** — requer apenas GPU.

| Papel | Modelo no nb03 (API) | Modelo no nb04 (local) |
|-------|----------------------|------------------------|
| Identificar provedor | Claude Sonnet 4.6 (vision) | Qwen2.5-VL-72B-Instruct-AWQ |
| Detecção visual | Florence-2-large-ft | Florence-2-large-ft (mesmo) |
| Classificar componentes | Claude Sonnet 4.6 (vision) | Qwen2.5-VL-72B-Instruct-AWQ |
| Analisar topologia | Claude Sonnet 4.6 (vision) | Qwen2.5-VL-72B-Instruct-AWQ |
| Análise STRIDE | Claude Sonnet 4.6 (text) | Qwen2.5-VL-72B-Instruct-AWQ |

**Gestão de memória GPU**: Florence-2 (~1.5 GB) e Qwen2.5-VL-72B-AWQ (~40 GB) não cabem simultaneamente. O pipeline carrega/descarrega os modelos conforme necessário, liberando VRAM entre etapas.

**Fallback**: Se o modelo 72B não estiver disponível, utiliza automaticamente `Qwen2.5-VL-7B-Instruct`.

**Etapas**:
1. Mesmo pipeline do nb03, substituindo chamadas Claude API por inferência local no VLM
2. Detecta automaticamente as imagens disponíveis na pasta do Google Drive e processa todas
3. Visualização, métricas e comparativo de custo (API vs local)

**Output**: Relatórios completos para cada arquitetura (JSON + HTML + imagens anotadas)

---

## 9. Referências

- [Metodologia STRIDE - Microsoft](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [Florence-2-large-ft - Microsoft (Hugging Face)](https://huggingface.co/microsoft/Florence-2-large-ft)
- [Claude API - Models (Anthropic)](https://platform.claude.com/docs/en/build-with-claude/models)
- [Claude Vision API (Anthropic)](https://platform.claude.com/docs/en/build-with-claude/vision)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Azure Security Benchmark - Microsoft](https://learn.microsoft.com/en-us/security/benchmark/azure/overview)
- [Google Cloud Architecture Framework - Security](https://cloud.google.com/architecture/framework/security)
- [Qwen2.5-VL - Alibaba (Hugging Face)](https://huggingface.co/Qwen/Qwen2.5-VL-72B-Instruct-AWQ)
- [Supervision - Roboflow](https://supervision.roboflow.com/)
- [Google Colab](https://colab.google/)
