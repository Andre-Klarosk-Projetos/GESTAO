# Gestão Comercial Web

Sistema web completo de gestão comercial em **HTML, CSS e JavaScript puro**, com **Firebase Authentication** e **Cloud Firestore**.

## Estrutura do projeto

```text
gestao-comercial/
├─ index.html
├─ firebase.json
├─ .firebaserc
├─ firestore.rules
├─ README.md
└─ assets/
   ├─ css/
   │  └─ styles.css
   └─ js/
      ├─ app.js
      ├─ firebase-config.js
      └─ services/
         ├─ auth.js
         ├─ db.js
         └─ utils.js
```

## Funcionalidades implementadas

- Login com Firebase Authentication
- Controle de acesso por função e por áreas liberadas
- Bloqueio de login para usuários inativos
- Cadastro, edição, ativação/inativação e exclusão lógica de usuários
- Cadastro e manutenção de produtos
- Tela de produtos responsiva e otimizada para celular
- Venda com múltiplos produtos, desconto, forma de pagamento, valor pago e troco
- Impressão de cupom não fiscal
- Busca de produtos por nome e código de barras
- Leitura por câmera via `BarcodeDetector` quando disponível no navegador
- Dashboard com indicadores operacionais
- Relatórios de estoque, baixa saída, mais vendidos, fornecedor e fabricante
- Tele-entregas com criação, edição, conclusão, cancelamento e reagendamento
- Sino de alertas de estoque baixo com atualização automática
- Troca de senha do usuário autenticado

## Estrutura sugerida do Firestore

### Collection `users`
Documento por UID do Authentication.

```json
{
  "fullName": "Administrador Master",
  "username": "admin",
  "email": "admin@gestao.local",
  "role": "Administrador",
  "permissions": ["dashboard", "sales", "products", "reports", "deliveries", "users", "settings"],
  "active": true,
  "deleted": false,
  "createdBy": "uid-do-criador",
  "createdAt": "timestamp",
  "updatedAt": "timestamp"
}
```

### Collection `products`
```json
{
  "name": "Produto Exemplo",
  "serialNumber": "SER-001",
  "supplier": "Fornecedor X",
  "costPrice": 100,
  "salePrice": 150,
  "barcode": "7890000000000",
  "quantity": 10,
  "brand": "Marca Y",
  "manufacturer": "Fabricante Z",
  "status": "ativo",
  "deleted": false,
  "createdAt": "timestamp",
  "updatedAt": "timestamp"
}
```

### Collection `sales`
```json
{
  "customerName": "Cliente balcão",
  "paymentMethod": "PIX",
  "discount": 0,
  "subtotal": 300,
  "total": 300,
  "amountPaid": 300,
  "change": 0,
  "cashierId": "uid",
  "cashierName": "João",
  "items": [
    {
      "productId": "abc123",
      "name": "Produto Exemplo",
      "quantity": 2,
      "unitPrice": 150,
      "total": 300
    }
  ],
  "createdAt": "timestamp",
  "updatedAt": "timestamp"
}
```

### Collection `deliveries`
```json
{
  "clientName": "Maria",
  "phone": "(00) 00000-0000",
  "address": "Rua Exemplo, 123",
  "description": "Entrega de 2 itens",
  "notes": "Portão azul",
  "amount": 25,
  "paymentMethod": "Dinheiro",
  "date": "2026-04-14",
  "time": "14:30",
  "status": "Agendado",
  "scheduledAt": "timestamp",
  "assignedUserId": "uid",
  "assignedUserName": "Carlos",
  "createdAt": "timestamp",
  "updatedAt": "timestamp"
}
```

### Collection `settings`
```json
{
  "scope": "system",
  "storeName": "Minha Loja",
  "address": "Meu Endereço",
  "lowStockThreshold": 5,
  "warrantyText": "Garantia conforme política da loja.",
  "createdAt": "timestamp",
  "updatedAt": "timestamp"
}
```

## Como configurar no Firebase

### 1. Criar projeto e habilitar serviços
No console do Firebase:
- habilite **Authentication > Sign-in method > Email/Password**
- habilite **Cloud Firestore** em modo produção
- copie `firestore.rules` para suas regras

### 2. Criar usuário master no Authentication
Crie manualmente o primeiro usuário em **Authentication > Users**.
Exemplo:
- e-mail: `admin@gestao.local`
- senha: defina uma senha forte

### 3. Criar documento do master em `users`
Depois de criar o usuário no Authentication, pegue o UID dele e crie manualmente em **Firestore > users/{UID}**:

```json
{
  "fullName": "Administrador Master",
  "username": "admin",
  "email": "admin@gestao.local",
  "role": "Administrador",
  "permissions": ["dashboard", "sales", "products", "reports", "deliveries", "users", "settings"],
  "active": true,
  "deleted": false
}
```

### 4. Publicar regras
Você pode colar o conteúdo de `firestore.rules` diretamente no console, ou publicar via CLI.

## Como rodar localmente

Como o projeto usa módulos ES e Firebase via CDN, rode com um servidor local simples.

### Opção A: VS Code + Live Server
- abra a pasta do projeto
- clique com o botão direito em `index.html`
- use **Open with Live Server**

### Opção B: Python local
Dentro da pasta do projeto:

```bash
python -m http.server 5500
```

Depois abra no navegador:

```text
http://localhost:5500
```

## Como publicar no Firebase Hosting

### 1. Instalar CLI
```bash
npm install -g firebase-tools
```

### 2. Fazer login
```bash
firebase login
```

### 3. Entrar na pasta do projeto
```bash
cd gestao-comercial
```

### 4. Publicar
```bash
firebase deploy
```

Isso publicará:
- Hosting
- Firestore Rules

## Regras de acesso implementadas

### Perfis e áreas padrão
- **Administrador**: tudo
- **Gerente**: dashboard, vendas, produtos, relatórios e entregas
- **Vendedor**: dashboard, vendas, produtos e entregas
- **Estoque**: dashboard, produtos e relatórios
- **Entregador**: somente entregas

Além do perfil, o cadastro do usuário também guarda a lista exata de áreas liberadas. O sistema usa:
- verificação visual na interface
- proteção no Firestore Rules

## Observações importantes

- O Firebase Authentication exige e-mail; por isso o sistema converte o campo `usuário` em e-mail interno no formato `usuario@gestao.local`.
- O cadastro de novos usuários é feito pelo administrador usando uma **instância secundária do Firebase App**, permitindo criar usuários sem desconectar o admin atual.
- A leitura por câmera depende de navegador compatível com `BarcodeDetector`. Em navegadores sem suporte, a busca manual continua funcionando.
- Exclusão de produtos e usuários é lógica, preservando histórico.

## Melhorias futuras sugeridas

- impressão térmica ESC/POS
- exportação de relatórios em PDF e Excel
- controle de caixa por turno
- auditoria detalhada por usuário
- página separada para entregador em modo ultrassimplificado
- integração com Storage para anexos e comprovantes
