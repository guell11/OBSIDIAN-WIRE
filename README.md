<div align="center">

# ⬛ OBSIDIAN WIRE
### K-PROTOCOL · POST-QUANTUM VAULT

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![Cryptography](https://img.shields.io/badge/Crypto-AES--256--GCM-00a884?style=flat-square)](#)
[![Post-Quantum](https://img.shields.io/badge/PQC-CRYSTALS--Kyber512-ff0055?style=flat-square)](#)
[![NIST](https://img.shields.io/badge/NIST-FIPS%20204-orange?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](#)

> *"Se a criptografia não sobrevive ao amanhã, ela já está morta hoje."*

**Obsidian Wire** é uma arquitetura de cofre de mensagens *Zero-Trust*, *Stateless* e
**Resistente à Computação Quântica**, projetada para cenários onde adversários estatais,
apreensão física de servidores e a tática **Harvest Now, Decrypt Later (HNDL)** são
ameaças ativas e reais.

[Demonstração](#-como-rodar) · [Arquitetura](#-arquitetura-de-segurança) · [Threat Model](#-threat-model)

</div>

---

## 🧬 Por que Obsidian Wire existe

Aplicativos de mensagens convencionais falham em cenários de ameaça extrema por razões
estruturais, não de implementação:

| Problema Convencional | Solução Obsidian Wire |
|---|---|
| Servidor conhece as chaves de sessão | Servidor armazena apenas blobs cifrados — nunca chaves |
| Criptografia baseada em curvas elípticas (ECDH) vulnerável a computadores quânticos | **CRYSTALS-Kyber512 KEM** (NIST FIPS 204) — resistente ao Algoritmo de Shor |
| Sessões armazenadas em banco de dados (comprometível por insider) | JWT Stateless assinado com HMAC-SHA256 + Device Fingerprinting |
| Cookie de sessão roubável por XSS ou rede | `HttpOnly` + `SameSite=Strict` + Fingerprint de hardware |
| Banco de dados legível se apreendido | DB contém apenas `IV` + `AES_Ciphertext` + `Kyber_Capsule` — entropia pura |


## 🛡️ Arquitetura de Segurança

### Camada 1 — ML-KEM (Post-Quantum Key Encapsulation)

O protocolo de estabelecimento de chave abandona ECDH e RSA — ambos quebráveis pelo
**Algoritmo de Shor** em hardware quântico — e adota **CRYSTALS-Kyber512**, o algoritmo
selecionado pelo NIST como padrão global de segurança pós-quântica (FIPS 204).

Alice gera (pk_A, sk_A) → Compartilha pk_A offline com o grupo
Bob roda: (capsule, sharedSecret) = Kyber.encap(pk_A)
Bob cifra: ciphertext = AES-256-GCM(sharedSecret, mensagem)
Bob envia ao servidor: { capsule, IV, ciphertext }

Alice recebe o pacote
Alice decapsula: sharedSecret = Kyber.decap(capsule, sk_A)
Alice decifra: plaintext = AES-256-GCM-Decrypt(sharedSecret, ciphertext)

O servidor **nunca** tocou em `sharedSecret`. O servidor **nunca** viu `plaintext`.
O banco de dados contém apenas `capsule + IV + ciphertext` — três pedaços de entropia.
Um computador quântico não consegue extrair `sharedSecret` da `capsule` sem `sk_A`,
porque o problema subjacente é **Module Learning with Errors (MLWE)**, não fatoração.

### Camada 2 — AES-256-GCM (Payload Encryption)

AES-256 é considerado **Quantum-Safe** contra o Algoritmo de Grover
(que reduz segurança de 256 bits para ~128 bits equivalentes — ainda impenetrável).
O modo **GCM (Galois/Counter Mode)** adiciona autenticação de mensagem (AEAD):
se um byte do ciphertext for alterado no banco de dados, a descriptografia falha
com `OperationError` — impedindo injeção silenciosa de dados falsos.

### Camada 3 — Identidade Stateless Anti-Hijacking

Login → Servidor emite JWT assinado com HMAC-SHA256
JWT payload: { uuid, username, device_fingerprint, exp }

device_fingerprint = SHA-256(User-Agent + IP)

- **Anti-Adulteração:** Se o cliente editar `uuid` no cookie para personificar outro
  usuário, a assinatura HMAC quebra e o servidor retorna HTTP 403.
- **Anti-Hijacking:** Se o cookie for roubado e usado em outro terminal,
  o fingerprint calculado não bate com o do JWT — sessão invalidada.
- **Anti-XSS:** `HttpOnly=True` impede que JavaScript leia o cookie.
- **Anti-CSRF:** `SameSite=Strict` impede requisições cross-origin.
- **Zero estado no servidor:** Não existe tabela de sessões. Não há nada para um
  atacante com acesso ao banco de dados extrair.

### Camada 4 — Blind Storage (Servidor Cego)

```sql
-- Isso é o que um atacante com acesso total ao banco de dados vê:
SELECT * FROM blind_message LIMIT 3;

author_uuid                          | iv             | ciphertext        | kyber_capsule
a1b2c3d4-...                         | 3q2+7w==       | Gk49Lp8mN...      | hX9Pq2mK...
f8e7d6c5-...                         | xK3nL9==       | Yw7Rt4sZ...       | qM2nX8pL...
´´´ 
Sem sk_A (que vive apenas na RAM do cliente e nunca é serializada),
as três colunas são matematicamente inúteis.

🎯 Threat Model
O que o Obsidian Wire MITIGA:
Vetor de Ataque	Status
Roubo físico do servidor / banco de dados	✅ DB contém apenas entropia
Harvest Now, Decrypt Later com computador quântico	✅ Kyber512 é MLWE-resistente ao Shor
Interceptação de tráfego (MITM mesmo com TLS quebrado)	✅ Payload interno requer sk_A
Session Hijacking por roubo de cookie	✅ Device Fingerprint + HttpOnly
Adulteração de identidade (UUID spoofing)	✅ HMAC-SHA256 invalida token adulterado
Injeção de mensagens falsas no banco	✅ GCM Authentication Tag rejeita dados alterados
Insider threat (admin do servidor)	✅ Admin não tem chaves, só vê blobs
XSS cookie theft	✅ HttpOnly bloqueia acesso JS
O que o Obsidian Wire NÃO MITIGA (Camadas fora do escopo):
Vetor	Motivo
Malware / Keylogger no dispositivo do cliente	Se o OS está comprometido, a chave vaza antes de chegar ao motor
Engenharia social	Matemática não protege contra humanos entregando a chave
Câmera filmando a tela	Fora do escopo de criptografia de software
Análise de tráfego de metadados avançada	Quem fala com quem e quando é parcialmente observável
🚀 Como Rodar
Requisitos
Python 3.10+

pip

Instalação
bash
# 1. Clone
git clone https://github.com/seu-usuario/obsidian-wire.git
cd obsidian-wire

# 2. Instale dependências
pip install -r requirements.txt

# 3. Gere a chave de identidade (OBRIGATÓRIO em produção)
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(64))')"

# 4. Inicie o servidor
python app.py
Acesse http://localhost:5000

Fluxo de uso
text
1. Registre dois usuários (Alice e Bob) em navegadores diferentes
2. Alice abre o chat → sistema gera par de chaves Kyber na RAM
3. Alice copia sua Chave Pública Kyber (exibida na interface)
4. Bob faz o mesmo
5. Alice cola a Chave Pública do Bob no campo "Destinatário" e ativa
6. Bob cola a Chave Pública da Alice e ativa
7. Agora as mensagens trafegam com KEM pós-quântico completo
📁 Estrutura do Projeto
text
obsidian-wire/
├── app.py              # Backend Flask (Auth + Vault API)
├── requirements.txt    # Dependências Python
├── README.md           # Este arquivo
└── templates/
    ├── login.html      # Autenticação (CSS + JS embutidos)
    ├── register.html   # Registro (CSS + JS embutidos)
    └── chat.html       # Vault / Chat (Motor Kyber + UI embutidos)

<div align="center">
Built with paranoia. Secured with mathematics.

"In math we trust — in humans, we encrypt anyway."

</div> 
