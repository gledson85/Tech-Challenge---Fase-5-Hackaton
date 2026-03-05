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

### 3.1 Pipeline Completo

```
Imagem de Arquitetura (.png)
        |
  [Passo 1] Identificar provedor cloud (AWS / Azure)
        |
  [Passo 2] Detectar componentes (Florence-2 + Claude Vision)
        |
  [Passo 3] Análise STRIDE por componente (Claude API)
        |
  [Passo 4] Relatório de Ameaças (JSON + HTML)
```

### 3.2 Detalhamento dos Passos

#### Passo 1 - Identificação do Provedor Cloud

O sistema recebe uma imagem de diagrama de arquitetura e identifica automaticamente se pertence à AWS ou Azure. Isso é feito via análise visual de:
- Logotipos e ícones característicos de cada provedor
- Paleta de cores (laranja/amarelo para AWS, azul para Azure)
- Nomenclatura dos serviços presentes na imagem

**Modelo utilizado**: Claude Vision API (multimodal)
**Input**: Imagem PNG do diagrama
**Output**: String identificando o provedor (`"AWS"` ou `"Azure"`)

#### Passo 2 - Detecção de Componentes

Dois modelos trabalham em conjunto:

**Florence-2-large-ft** (Microsoft, pré-treinado fine-tuned):
- Modelo de visão computacional com 770M de parâmetros (versão fine-tuned para melhor detecção)
- Realiza detecção zero-shot com 5 estratégias complementares:
  - `OCR_WITH_REGION`: detecta textos (nomes dos serviços) com bounding boxes
  - `CAPTION_TO_PHRASE_GROUNDING`: localiza termos específicos de componentes cloud (1 serviço por query)
  - `REGION_PROPOSAL`: propostas genéricas de regiões de interesse
  - `DENSE_REGION_CAPTION`: regiões com legenda densa
  - `OD`: detecção de objetos (complementar)
- Tiling 3x3 com 20% de overlap: repete todas as estratégias em cada tile para capturar componentes menores
- Filtros relaxados para diagramas técnicos (min_area_ratio=0.0005, max_area_ratio=0.8, min_size=5px)
- NMS (Non-Maximum Suppression) com IoU > 0.5 para remover duplicatas

**Claude Vision API** (classificação refinada):
- Recebe os recortes (crops) de cada bounding box detectado pelo Florence-2
- Classifica cada componente com nome específico do serviço cloud
- Contextualiza o componente dentro da arquitetura (função, conexões)

**Input**: Imagem PNG do diagrama
**Output**: Lista de componentes detectados com:
- Nome do serviço (ex: "Amazon RDS", "API Gateway")
- Classe genérica (ex: "database", "api_gateway")
- Bounding box (coordenadas x, y, largura, altura)
- Provedor cloud (AWS / Azure)

#### Passo 3 - Análise STRIDE

Para cada componente detectado, o Claude API gera uma análise STRIDE completa:

**Input**: Lista de componentes + provedor cloud + contexto da arquitetura
**Output**: Para cada componente:
- Ameaças identificadas por categoria STRIDE (S/T/R/I/D/E)
- Nível de risco (Alto / Médio / Baixo)
- Contramedidas recomendadas para cada ameaça
- Referências a boas práticas do provedor (AWS Well-Architected / Azure Security Benchmark)

#### Passo 4 - Geração do Relatório

O sistema consolida toda a análise em dois formatos:

**JSON estruturado**: Para integração com outros sistemas
```json
{
  "provider": "AWS",
  "image": "arquitetura_1.png",
  "components": [
    {
      "name": "Amazon RDS (Primary)",
      "class": "database",
      "bbox": [184, 462, 112, 75],
      "threats": {
        "spoofing": {
          "description": "Acesso não autenticado ao banco de dados",
          "risk": "Alto",
          "countermeasure": "Habilitar IAM Database Authentication + Security Groups restritivos"
        }
      }
    }
  ],
  "summary": {}
}
```

**HTML formatado**: Para apresentação e documentação, contendo:
- Capa com dados do projeto
- Tabela de componentes detectados
- Análise STRIDE detalhada por componente com badges coloridas de risco
- Resumo executivo com principais riscos e recomendações
- CSS inline (sem dependências externas), pode ser salvo como PDF pelo navegador (Ctrl+P)

---

## 4. Classes de Detecção

### 4.1 Categorias de Componentes

```python
CLASSES = {
    # Rede e Segurança
    'waf_firewall':      ['AWS WAF', 'AWS Shield', 'Azure Firewall'],
    'cdn':               ['Amazon CloudFront', 'Azure CDN'],
    'load_balancer':     ['ALB', 'NLB', 'Azure Load Balancer'],
    'vpc_vnet':          ['VPC', 'VNet', 'Subnet'],

    # Computação
    'compute':           ['EC2', 'SEI/SIP', 'App Service', 'VM'],
    'auto_scaling':      ['Auto Scaling Group', 'VMSS'],
    'orchestrator':      ['Logic Apps', 'Step Functions', 'Lambda'],

    # Dados
    'database':          ['RDS', 'Aurora', 'Azure SQL', 'Cosmos DB'],
    'cache':             ['ElastiCache', 'Azure Cache for Redis'],
    'storage':           ['S3', 'EFS', 'Azure Blob', 'NFS'],

    # API e Integração
    'api_gateway':       ['API Gateway', 'Azure API Management'],
    'developer_portal':  ['Developer Portal'],
    'web_service':       ['REST', 'SOAP', 'SaaS Service'],

    # Identidade e Segurança
    'auth_identity':     ['IAM', 'Microsoft Entra', 'Cognito'],
    'kms_encryption':    ['AWS KMS', 'Azure Key Vault'],

    # Observabilidade
    'monitoring':        ['CloudWatch', 'CloudTrail', 'Azure Monitor'],
    'backup':            ['AWS Backup', 'Azure Backup'],

    # Mensageria
    'messaging':         ['SES', 'SQS', 'SNS', 'Azure Service Bus'],

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

O sistema será avaliado com duas arquiteturas de referência fornecidas no enunciado:

### 5.1 Arquitetura 1 - AWS

**Arquivo**: `arquitetura 1.png`

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

**Arquivo**: `arquitetura 2.png`

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

| Biblioteca | Versão | Uso |
|-----------|--------|-----|
| `transformers` | latest | Florence-2 (detecção de componentes) |
| `anthropic` | latest | Claude API (classificação + STRIDE) |
| `supervision` | latest | Visualização de bounding boxes |
| _(removido)_ | - | _(relatório agora em HTML, sem dependência de fpdf2)_ |
| `timm` | latest | Dependência do Florence-2 (modelos de visão) |
| `einops` | latest | Dependência do Florence-2 (operações tensoriais) |
| `torch` | latest | Backend para Florence-2 (pré-instalado no Colab) |
| `Pillow` | latest | Manipulação de imagens (pré-instalado no Colab) |
| `matplotlib` | latest | Visualizações (pré-instalado no Colab) |

> **Nota sobre `flash_attn`**: A biblioteca Flash Attention (`flash_attn`) seria utilizada para acelerar o mecanismo de atenção do Florence-2, reduzindo o consumo de memória GPU e aumentando a velocidade de inferência. Porém, a compilação falha no ambiente Google Colab devido a incompatibilidades com a versão do CUDA/compilador disponível. O Florence-2 funciona normalmente sem ela, utilizando a implementação padrão de atenção do PyTorch.

### 6.3 Modelos de IA

| Modelo | Provedor | Parâmetros | Uso no Projeto |
|--------|----------|-----------|----------------|
| **Florence-2-large-ft** | Microsoft | 770M | Detecção zero-shot de componentes visuais (bounding boxes) |
| **Claude Sonnet 4.6** | Anthropic | - | Identificação de provedor, classificação de componentes, análise STRIDE |

### 6.4 Estimativa de Custo por Imagem Analisada

Preços base do Claude Sonnet 4.6: **$3.00 / 1M tokens de input** e **$15.00 / 1M tokens de output**.

| Etapa | Chamadas API | Tokens Input | Tokens Output | Custo Input | Custo Output | Subtotal (USD) | Subtotal (BRL) |
|-------|-------------|-------------|--------------|-------------|-------------|---------------|---------------|
| Passo 1 — Identificar provedor | 1 | ~1.800 | ~50 | $0,005 | $0,001 | **$0,006** | **R$ 0,03** |
| Passo 2 — Classificação de componentes | ~15 | ~15.000 | ~2.500 | $0,045 | $0,038 | **$0,083** | **R$ 0,46** |
| Passo 3 — Análise STRIDE | 1 | ~3.000 | ~5.000 | $0,009 | $0,075 | **$0,084** | **R$ 0,46** |
| **Total por imagem** | **~17** | **~19.800** | **~7.550** | **$0,059** | **$0,114** | **~$0,17** | **~R$ 0,94** |

> **Custo estimado por imagem analisada: ~US$ 0,17 (~R$ 0,94)**
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
├── IADT - Fase 5 - Hackaton.pdf       # Enunciado do projeto
├── arquitetura 1.png                  # Diagrama AWS (teste)
├── arquitetura 2.png                  # Diagrama Azure (teste)
├── notebooks/
│   ├── 01_component_detection.ipynb   # Detecção de componentes
│   ├── 02_stride_analysis.ipynb       # Análise STRIDE
│   └── 03_consolidado.ipynb            # Pipeline consolidado end-to-end
└── outputs/
    ├── detections/                    # Imagens com bboxes anotados
    └── reports/                       # Relatórios STRIDE (JSON + HTML)
```

### 7.2 Google Drive

```
MyDrive/
└── hackaton-stride/
    ├── notebooks/                     # Notebooks do Colab
    ├── test_images/                   # Imagens de teste (arquitetura 1 e 2)
    └── outputs/
        ├── detections/                # Resultados da detecção
        └── reports/                   # Relatórios gerados (JSON + HTML)
```

---

## 8. Notebooks

### 8.1 Notebook 01 - Detecção de Componentes (`01_component_detection.ipynb`)

**GPU necessária**: T4 ou A100

**Etapas**:
1. Montar Google Drive e carregar imagem de teste
2. **Passo 1 - Identificar provedor**: Enviar imagem ao Claude Vision API com prompt para identificar se é AWS ou Azure
3. **Passo 2a - Detecção visual**: Carregar Florence-2 (`microsoft/Florence-2-large-ft`) e executar detecção com 5 estratégias (OCR, Phrase Grounding, Region Proposal, Dense Caption, OD) na imagem completa + tiling 3x3 com 20% overlap
4. **Passo 2b - Classificação**: Recortar cada região detectada (crop dos bounding boxes) e enviar ao Claude Vision para classificação refinada com nome exato do serviço
5. Salvar resultados em JSON (lista de componentes com bboxes e classes)
6. Visualizar imagem original com bounding boxes anotados usando `supervision`

**Output**: `outputs/detections/componentes_arquitetura_X.json`

### 8.2 Notebook 02 - Análise STRIDE (`02_stride_analysis.ipynb`)

**GPU necessária**: Nenhuma (apenas chamadas API)

**Etapas**:
1. Carregar JSON de componentes detectados
2. Para cada componente, montar prompt STRIDE contextualizado:
   - Nome e classe do componente
   - Provedor cloud (AWS/Azure)
   - Posição na arquitetura (se está em subnet pública/privada, etc.)
3. Enviar ao Claude API para análise STRIDE completa
4. Para cada ameaça, gerar contramedidas específicas do provedor
5. Consolidar em JSON estruturado
6. Gerar relatório HTML formatado (CSS inline, sem dependências externas)

**Output**:
- `outputs/reports/stride_arquitetura_X.json`
- `outputs/reports/stride_arquitetura_X.html`

### 8.3 Notebook 03 - Pipeline Consolidado (`03_consolidado.ipynb`)

**GPU necessária**: T4

**Etapas**:
1. Pipeline end-to-end: recebe imagem → identifica provedor → detecta componentes → analisa STRIDE → gera relatório
2. Executar para as duas arquiteturas de teste (AWS e Azure)
3. Visualização lado a lado: imagem com bboxes + resumo do relatório
4. Métricas de execução: tempo de processamento por etapa, número de componentes detectados, número de ameaças identificadas

**Output**: Relatórios completos para ambas as arquiteturas (JSON + HTML)

---

## 9. Backlog (Opcional - Se Sobrar Tempo)

Requisito acadêmico de treinamento supervisionado:

- [ ] Construir dataset de imagens de diagramas de arquitetura de software
- [ ] Anotar dataset no Roboflow com as classes definidas na seção 4.1
- [ ] Fine-tuning do YOLOv8 com o dataset anotado
- [ ] Avaliar modelo com métricas: mAP, Precision, Recall, F1-Score
- [ ] Comparar resultados do modelo treinado vs. abordagem zero-shot (Florence-2)

---

## 10. Entregáveis

Conforme definido no enunciado:

- [ ] **Documentação**: Este README + documentação nos notebooks
- [ ] **Vídeo**: Até 15 minutos explicando a solução proposta
- [ ] **Link do GitHub**: Este repositório

---

## 11. Referências

- [Metodologia STRIDE - Microsoft](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [Florence-2-large-ft - Microsoft (Hugging Face)](https://huggingface.co/microsoft/Florence-2-large-ft)
- [Claude API - Models (Anthropic)](https://platform.claude.com/docs/en/build-with-claude/models)
- [Claude Vision API (Anthropic)](https://platform.claude.com/docs/en/build-with-claude/vision)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- [Azure Security Benchmark - Microsoft](https://learn.microsoft.com/en-us/security/benchmark/azure/overview)
- [Supervision - Roboflow](https://supervision.roboflow.com/)
- [Google Colab](https://colab.google/)
- [Ultralytics YOLO](https://docs.ultralytics.com/)
