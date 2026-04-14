import { login, watchAuth, logout, createManagedUser, updateManagedUser, deleteManagedUser, changeCurrentPassword, listUsers } from './services/auth.js';
import { refs, createDoc, updateByPath, listCollection, subscribeCollection, orderBy, timestampFromDateTime } from './services/db.js';
import { AREAS, ROLES, currency, toNumber, formatDate, formatDateTime, formatRole, hasPermission, paymentMethods, deliveryStatuses, ensurePermissionsByRole } from './services/utils.js';

const els = {
  authView: document.getElementById('auth-view'),
  mainView: document.getElementById('main-view'),
  loginForm: document.getElementById('login-form'),
  loginIdentifier: document.getElementById('login-identifier'),
  loginPassword: document.getElementById('login-password'),
  authFeedback: document.getElementById('auth-feedback'),
  nav: document.getElementById('main-nav'),
  pageTitle: document.getElementById('page-title'),
  userName: document.getElementById('current-user-name'),
  userRole: document.getElementById('current-user-role'),
  logoutBtn: document.getElementById('logout-btn'),
  stockAlertBtn: document.getElementById('stock-alert-btn'),
  stockAlertCount: document.getElementById('stock-alert-count'),
  stockAlertPanel: document.getElementById('stock-alert-panel'),
  stockAlertList: document.getElementById('stock-alert-list'),
  modalRoot: document.getElementById('modal-root'),
  mobileMenuBtn: document.getElementById('mobile-menu-btn')
};

const tabEls = {
  dashboard: document.getElementById('tab-dashboard'),
  sales: document.getElementById('tab-sales'),
  products: document.getElementById('tab-products'),
  reports: document.getElementById('tab-reports'),
  deliveries: document.getElementById('tab-deliveries'),
  users: document.getElementById('tab-users'),
  settings: document.getElementById('tab-settings')
};

const state = {
  currentUser: null,
  users: [],
  products: [],
  sales: [],
  deliveries: [],
  settings: { storeName: 'Minha Loja', address: 'Endereço da loja', lowStockThreshold: 5, warrantyText: 'Garantia conforme política interna da loja.' },
  activeTab: 'dashboard',
  editingProductId: null,
  editingUserId: null,
  editingDeliveryId: null,
  cart: [],
  unsubscribe: []
};

function showFeedback(message, type = '') {
  els.authFeedback.textContent = message;
  els.authFeedback.className = `feedback ${type}`.trim();
}

function escapeHtml(value = '') {
  return String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\'' : '&#39;', '"': '&quot;' }[char]));
}

function renderApp() {
  renderDashboard();
  renderProducts();
  renderSales();
  renderReports();
  renderDeliveries();
  renderUsers();
  renderSettings();
  renderStockAlerts();
  refreshNavigationPermissions();
}

function setMainView(isAuthenticated) {
  els.authView.classList.toggle('hidden', isAuthenticated);
  els.mainView.classList.toggle('hidden', !isAuthenticated);
}

function refreshNavigationPermissions() {
  const buttons = [...els.nav.querySelectorAll('.nav-item')];
  buttons.forEach((button) => {
    const tab = button.dataset.tab;
    const allowed = hasPermission(state.currentUser, tab);
    button.classList.toggle('hidden', !allowed);
  });

  if (!hasPermission(state.currentUser, state.activeTab)) {
    const firstAllowed = AREAS.find((area) => hasPermission(state.currentUser, area)) || 'dashboard';
    activateTab(firstAllowed);
  }
}

function activateTab(tab) {
  state.activeTab = tab;
  const titleMap = {
    dashboard: 'Dashboard',
    sales: 'Vendas',
    products: 'Produtos',
    reports: 'Relatórios',
    deliveries: 'Tele-entregas',
    users: 'Usuários',
    settings: 'Configurações'
  };

  [...els.nav.querySelectorAll('.nav-item')].forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === tab));
  Object.entries(tabEls).forEach(([key, el]) => el.classList.toggle('active', key === tab));
  els.pageTitle.textContent = titleMap[tab] || 'Painel';
  document.querySelector('.sidebar')?.classList.remove('open');
}

async function bootstrapData() {
  state.unsubscribe.forEach((fn) => fn && fn());
  state.unsubscribe = [];

  state.unsubscribe.push(subscribeCollection('products', [orderBy('name')], (rows) => {
    state.products = rows.filter((item) => !item.deleted);
    renderProducts();
    renderSales();
    renderReports();
    renderDashboard();
    renderStockAlerts();
  }));

  state.unsubscribe.push(subscribeCollection('sales', [orderBy('createdAt', 'desc')], (rows) => {
    state.sales = rows;
    renderSales();
    renderReports();
    renderDashboard();
  }));

  state.unsubscribe.push(subscribeCollection('deliveries', [orderBy('scheduledAt', 'desc')], (rows) => {
    state.deliveries = rows;
    renderDeliveries();
    renderDashboard();
  }));

  if (state.currentUser?.role === 'Administrador') {
    state.users = await listUsers();
    renderUsers();
  }

  const settingsList = await listCollection('settings');
  const systemSettings = settingsList.find((item) => item.scope === 'system');
  if (systemSettings) state.settings = { ...state.settings, ...systemSettings };
  renderSettings();
  renderStockAlerts();
}

function renderDashboard() {
  const lowStock = getLowStockProducts();
  const todaySales = state.sales.filter((sale) => new Date(sale.createdAt?.toDate?.() || sale.createdAt || 0).toDateString() === new Date().toDateString());
  const todayRevenue = todaySales.reduce((sum, sale) => sum + Number(sale.total || 0), 0);
  const activeDeliveries = state.deliveries.filter((item) => ['Agendado', 'Em rota', 'Reagendado', 'Recolhimento'].includes(item.status));
  const totalStock = state.products.reduce((sum, item) => sum + Number(item.quantity || 0), 0);

  tabEls.dashboard.innerHTML = `
    <div class="stats-grid">
      <div class="metric-card"><span>Faturamento de hoje</span><strong>${currency(todayRevenue)}</strong></div>
      <div class="metric-card"><span>Itens em estoque</span><strong>${totalStock}</strong></div>
      <div class="metric-card"><span>Alertas de estoque</span><strong>${lowStock.length}</strong></div>
    </div>
    <div class="dashboard-grid" style="margin-top:18px;">
      <div class="card">
        <div class="section-header"><h2>Últimas vendas</h2><span class="muted">Resumo em tempo real</span></div>
        <div class="list-group">
          ${state.sales.slice(0, 6).map((sale) => `
            <div class="list-item">
              <strong>${sale.customerName || 'Venda balcão'} · ${currency(sale.total)}</strong>
              <span>${formatDateTime(sale.createdAt)} · ${sale.paymentMethod || '-'}</span>
            </div>`).join('') || '<div class="empty-state">Nenhuma venda registrada.</div>'}
        </div>
      </div>
      <div class="card">
        <div class="section-header"><h2>Entregas e recolhimentos</h2><span class="muted">${activeDeliveries.length} em aberto</span></div>
        <div class="list-group">
          ${activeDeliveries.slice(0, 6).map((item) => `
            <div class="delivery-item">
              <strong>${item.clientName}</strong>
              <span>${item.address}</span>
              <span>${formatDate(item.scheduledAt)} ${item.time || ''} · ${item.status}</span>
            </div>`).join('') || '<div class="empty-state">Sem atendimentos pendentes.</div>'}
        </div>
      </div>
    </div>
    <div class="cards-grid" style="margin-top:18px;">
      <div class="card"><h3>Produtos com estoque baixo</h3>${renderSimpleList(lowStock.map((item) => `${item.name} · ${item.quantity} un.`))}</div>
      <div class="card"><h3>Mais vendidos</h3>${renderSimpleList(getTopSelling().map((item) => `${item.name} · ${item.qty} un.`))}</div>
      <div class="card"><h3>Baixa saída</h3>${renderSimpleList(getLowSelling().map((item) => `${item.name} · ${item.qty} un.`))}</div>
      <div class="card"><h3>Equipe</h3>${renderSimpleList(state.users.slice(0, 6).map((item) => `${item.fullName} · ${item.role}`))}</div>
    </div>
  `;
}

function renderSimpleList(items) {
  if (!items.length) return '<div class="empty-state">Nada para exibir.</div>';
  return `<div class="list-group">${items.map((text) => `<div class="list-item">${escapeHtml(text)}</div>`).join('')}</div>`;
}

function renderProducts() {
  if (!hasPermission(state.currentUser, 'products')) {
    tabEls.products.innerHTML = renderBlocked();
    return;
  }

  const rows = state.products.map((product) => `
    <tr>
      <td>${escapeHtml(product.name)}</td>
      <td>${escapeHtml(product.serialNumber || '-')}</td>
      <td>${escapeHtml(product.brand || '-')}</td>
      <td>${escapeHtml(product.supplier || '-')}</td>
      <td>${currency(product.costPrice)}</td>
      <td>${currency(product.salePrice)}</td>
      <td>${product.quantity ?? 0}</td>
      <td><span class="tag ${product.status === 'ativo' ? 'success' : 'warning'}">${product.status || 'ativo'}</span></td>
      <td>
        <div class="inline-row">
          <button class="btn btn-secondary" data-product-edit="${product.id}">Editar</button>
          <button class="btn btn-danger" data-product-delete="${product.id}">Inativar</button>
        </div>
      </td>
    </tr>
  `).join('');

  tabEls.products.innerHTML = `
    <div class="products-layout">
      <div class="panel">
        <div class="section-header"><h2>${state.editingProductId ? 'Editar produto' : 'Cadastro de produtos'}</h2><span class="muted">Otimizado para celular e desktop</span></div>
        <form id="product-form" class="form-grid mobile-optimized">
          <label>Nome do produto<input name="name" required /></label>
          <label>Número de série<input name="serialNumber" /></label>
          <label>Fornecedor<input name="supplier" /></label>
          <label>Preço de custo<input name="costPrice" type="number" step="0.01" min="0" /></label>
          <label>Preço de venda<input name="salePrice" type="number" step="0.01" min="0" required /></label>
          <label>Código de barras<input name="barcode" /></label>
          <label>Quantidade<input name="quantity" type="number" step="1" min="0" required /></label>
          <label>Marca<input name="brand" /></label>
          <label>Fabricante<input name="manufacturer" /></label>
          <label>Status<select name="status"><option value="ativo">Ativo</option><option value="inativo">Inativo</option></select></label>
          <div class="form-actions" style="grid-column: 1 / -1;">
            <button class="btn btn-primary" type="submit">${state.editingProductId ? 'Salvar alterações' : 'Cadastrar produto'}</button>
            <button class="btn btn-secondary" type="button" id="product-reset-btn">Limpar</button>
          </div>
        </form>
      </div>
      <div class="table-card">
        <div class="section-header"><h2>Lista de produtos</h2></div>
        <div class="search-row">
          <input id="product-filter-input" placeholder="Pesquisar por nome, código de barras, fornecedor ou marca" />
          <select id="product-status-filter"><option value="">Todos os status</option><option value="ativo">Ativo</option><option value="inativo">Inativo</option></select>
          <button class="btn btn-secondary" id="product-filter-btn">Filtrar</button>
        </div>
        <div class="table-wrap" style="margin-top:14px;">
          <table>
            <thead><tr><th>Produto</th><th>Série</th><th>Marca</th><th>Fornecedor</th><th>Custo</th><th>Venda</th><th>Qtd</th><th>Status</th><th>Ações</th></tr></thead>
            <tbody id="products-tbody">${rows || '<tr><td colspan="9">Nenhum produto cadastrado.</td></tr>'}</tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  const form = tabEls.products.querySelector('#product-form');
  const filterInput = tabEls.products.querySelector('#product-filter-input');
  const statusFilter = tabEls.products.querySelector('#product-status-filter');

  if (state.editingProductId) {
    const editing = state.products.find((item) => item.id === state.editingProductId);
    if (editing) Object.entries(editing).forEach(([key, value]) => form.elements[key] && (form.elements[key].value = value ?? ''));
  }

  form.addEventListener('submit', handleProductSubmit);
  tabEls.products.querySelector('#product-reset-btn').addEventListener('click', () => { state.editingProductId = null; renderProducts(); });
  tabEls.products.querySelector('#product-filter-btn').addEventListener('click', () => applyProductFilter(filterInput.value, statusFilter.value));
  bindProductTableActions(tabEls.products);
}

function bindProductTableActions(scope) {
  scope.querySelectorAll('[data-product-edit]').forEach((btn) => btn.addEventListener('click', () => { state.editingProductId = btn.dataset.productEdit; renderProducts(); }));
  scope.querySelectorAll('[data-product-delete]').forEach((btn) => btn.addEventListener('click', async () => {
    await updateByPath('products', btn.dataset.productDelete, { deleted: true, status: 'inativo' });
  }));
}

function applyProductFilter(text, status) {
  const tbody = tabEls.products.querySelector('#products-tbody');
  const term = text.trim().toLowerCase();
  const filtered = state.products.filter((product) => {
    const haystack = [product.name, product.barcode, product.supplier, product.brand, product.manufacturer].join(' ').toLowerCase();
    const matchesTerm = !term || haystack.includes(term);
    const matchesStatus = !status || product.status === status;
    return matchesTerm && matchesStatus;
  });

  tbody.innerHTML = filtered.map((product) => `
    <tr>
      <td>${escapeHtml(product.name)}</td><td>${escapeHtml(product.serialNumber || '-')}</td><td>${escapeHtml(product.brand || '-')}</td><td>${escapeHtml(product.supplier || '-')}</td>
      <td>${currency(product.costPrice)}</td><td>${currency(product.salePrice)}</td><td>${product.quantity ?? 0}</td><td>${product.status || 'ativo'}</td>
      <td><div class="inline-row"><button class="btn btn-secondary" data-product-edit="${product.id}">Editar</button><button class="btn btn-danger" data-product-delete="${product.id}">Inativar</button></div></td>
    </tr>`).join('') || '<tr><td colspan="9">Nenhum resultado encontrado.</td></tr>';
  bindProductTableActions(tabEls.products);
}

async function handleProductSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = Object.fromEntries(new FormData(form).entries());
  payload.costPrice = toNumber(payload.costPrice);
  payload.salePrice = toNumber(payload.salePrice);
  payload.quantity = toNumber(payload.quantity);
  payload.status = payload.status || 'ativo';
  payload.deleted = false;

  if (state.editingProductId) {
    await updateByPath('products', state.editingProductId, payload);
    state.editingProductId = null;
  } else {
    await createDoc(refs.products, payload);
  }
  form.reset();
}

function renderSales() {
  if (!hasPermission(state.currentUser, 'sales')) {
    tabEls.sales.innerHTML = renderBlocked();
    return;
  }

  const cartTotal = calculateCartTotal();
  tabEls.sales.innerHTML = `
    <div class="sales-layout">
      <div class="panel">
        <div class="section-header"><h2>Novo atendimento</h2><span class="muted">Busca por nome, código de barras e leitor por câmera</span></div>
        <div class="search-row">
          <input id="sale-product-search" placeholder="Pesquisar produto por nome ou código de barras" />
          <button id="sale-product-search-btn" class="btn btn-secondary">Buscar</button>
          <button id="camera-scan-btn" class="btn btn-primary">Ler pela câmera</button>
        </div>
        <div id="sale-search-results" class="stack-list" style="margin-top:14px;"></div>
        <div class="scanner-card" style="margin-top:14px;">
          <h3>Leitor por câmera</h3>
          <video id="barcode-video" class="video-preview" autoplay muted playsinline></video>
          <div class="inline-row" style="margin-top:10px;"><span class="muted">Usa <span class="kbd">BarcodeDetector</span> quando disponível.</span><button id="stop-scan-btn" class="btn btn-secondary">Parar câmera</button></div>
        </div>
      </div>
      <div class="panel">
        <div class="section-header"><h2>Itens da venda</h2><span class="muted">${state.cart.length} item(ns)</span></div>
        <div id="cart-list" class="cart-list">${renderCartItems()}</div>
        <form id="sale-form" class="form-grid" style="margin-top:16px;">
          <label>Cliente<input name="customerName" placeholder="Opcional" /></label>
          <label>Forma de pagamento<select name="paymentMethod">${paymentMethods.map((item) => `<option value="${item}">${item}</option>`).join('')}</select></label>
          <label>Desconto<input name="discount" type="number" step="0.01" min="0" value="0" /></label>
          <label>Valor pago<input name="amountPaid" type="number" step="0.01" min="0" value="0" /></label>
          <div class="summary-box" style="grid-column: 1 / -1;">
            <div class="summary-line"><span>Subtotal</span><strong id="sale-subtotal">${currency(cartTotal.subtotal)}</strong></div>
            <div class="summary-line"><span>Desconto</span><strong id="sale-discount-view">${currency(cartTotal.discount)}</strong></div>
            <div class="summary-line total"><span>Total</span><strong id="sale-total">${currency(cartTotal.total)}</strong></div>
            <div class="summary-line"><span>Troco</span><strong id="sale-change">${currency(cartTotal.change)}</strong></div>
          </div>
          <div class="form-actions" style="grid-column: 1 / -1;">
            <button class="btn btn-success" type="submit">Finalizar venda</button>
            <button class="btn btn-secondary" type="button" id="clear-cart-btn">Limpar carrinho</button>
          </div>
        </form>
      </div>
    </div>
    <div class="table-card" style="margin-top:18px;">
      <div class="section-header"><h2>Histórico recente</h2></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Data</th><th>Cliente</th><th>Total</th><th>Pagamento</th><th>Itens</th></tr></thead>
          <tbody>
            ${state.sales.slice(0, 10).map((sale) => `<tr><td>${formatDateTime(sale.createdAt)}</td><td>${escapeHtml(sale.customerName || 'Balcão')}</td><td>${currency(sale.total)}</td><td>${escapeHtml(sale.paymentMethod || '-')}</td><td>${sale.items?.length || 0}</td></tr>`).join('') || '<tr><td colspan="5">Nenhuma venda registrada.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  `;

  tabEls.sales.querySelector('#sale-product-search-btn').addEventListener('click', handleSaleSearch);
  tabEls.sales.querySelector('#sale-product-search').addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); handleSaleSearch(); } });
  tabEls.sales.querySelector('#sale-form').addEventListener('submit', handleSaleSubmit);
  tabEls.sales.querySelector('#clear-cart-btn').addEventListener('click', () => { state.cart = []; renderSales(); });
  tabEls.sales.querySelector('#camera-scan-btn').addEventListener('click', startCameraScan);
  tabEls.sales.querySelector('#stop-scan-btn').addEventListener('click', stopCameraScan);
  bindCartButtons();
  const discountField = tabEls.sales.querySelector('input[name="discount"]');
  const paidField = tabEls.sales.querySelector('input[name="amountPaid"]');
  [discountField, paidField].forEach((field) => field.addEventListener('input', () => updateSaleSummary()));
}

function renderCartItems() {
  if (!state.cart.length) return '<div class="empty-state">Nenhum item adicionado.</div>';
  return state.cart.map((item) => `
    <div class="cart-item">
      <div class="cart-line"><strong>${escapeHtml(item.name)}</strong><span>${currency(item.salePrice)}</span></div>
      <div class="cart-line"><span>Qtd: ${item.quantity}</span><span>Total: ${currency(item.salePrice * item.quantity)}</span></div>
      <div class="cart-actions">
        <button class="btn btn-secondary" data-cart-decrease="${item.id}">-1</button>
        <button class="btn btn-secondary" data-cart-increase="${item.id}">+1</button>
        <button class="btn btn-danger" data-cart-remove="${item.id}">Remover</button>
      </div>
    </div>
  `).join('');
}

function handleSaleSearch() {
  const term = tabEls.sales.querySelector('#sale-product-search').value.trim().toLowerCase();
  const resultsEl = tabEls.sales.querySelector('#sale-search-results');
  const results = state.products.filter((product) => product.status !== 'inativo' && [product.name, product.barcode].join(' ').toLowerCase().includes(term)).slice(0, 8);

  resultsEl.innerHTML = results.map((product) => `
    <div class="list-item">
      <strong>${escapeHtml(product.name)}</strong>
      <span>${escapeHtml(product.barcode || 'Sem código')} · Estoque: ${product.quantity}</span>
      <div class="inline-row" style="margin-top:8px;"><button class="btn btn-primary" data-add-cart="${product.id}">Adicionar</button></div>
    </div>
  `).join('') || '<div class="empty-state">Nenhum produto encontrado.</div>';

  resultsEl.querySelectorAll('[data-add-cart]').forEach((btn) => btn.addEventListener('click', () => addProductToCart(btn.dataset.addCart)));
}

function addProductToCart(productId) {
  const product = state.products.find((item) => item.id === productId);
  if (!product) return;
  const existing = state.cart.find((item) => item.id === productId);
  if (existing) existing.quantity += 1;
  else state.cart.push({ id: product.id, name: product.name, salePrice: Number(product.salePrice || 0), quantity: 1, barcode: product.barcode });
  renderSales();
  bindCartButtons();
}

function bindCartButtons() {
  tabEls.sales.querySelectorAll('[data-cart-decrease]').forEach((btn) => btn.addEventListener('click', () => {
    const item = state.cart.find((row) => row.id === btn.dataset.cartDecrease);
    if (!item) return;
    item.quantity = Math.max(1, item.quantity - 1);
    renderSales();
    bindCartButtons();
  }));
  tabEls.sales.querySelectorAll('[data-cart-increase]').forEach((btn) => btn.addEventListener('click', () => {
    const item = state.cart.find((row) => row.id === btn.dataset.cartIncrease);
    if (!item) return;
    item.quantity += 1;
    renderSales();
    bindCartButtons();
  }));
  tabEls.sales.querySelectorAll('[data-cart-remove]').forEach((btn) => btn.addEventListener('click', () => {
    state.cart = state.cart.filter((row) => row.id !== btn.dataset.cartRemove);
    renderSales();
    bindCartButtons();
  }));
}

function calculateCartTotal() {
  const discountInput = tabEls.sales?.querySelector('input[name="discount"]');
  const paidInput = tabEls.sales?.querySelector('input[name="amountPaid"]');
  const subtotal = state.cart.reduce((sum, item) => sum + (Number(item.salePrice) * Number(item.quantity)), 0);
  const discount = toNumber(discountInput?.value || 0);
  const total = Math.max(0, subtotal - discount);
  const amountPaid = toNumber(paidInput?.value || 0);
  const change = Math.max(0, amountPaid - total);
  return { subtotal, discount, total, amountPaid, change };
}

function updateSaleSummary() {
  const { subtotal, discount, total, change } = calculateCartTotal();
  tabEls.sales.querySelector('#sale-subtotal').textContent = currency(subtotal);
  tabEls.sales.querySelector('#sale-discount-view').textContent = currency(discount);
  tabEls.sales.querySelector('#sale-total').textContent = currency(total);
  tabEls.sales.querySelector('#sale-change').textContent = currency(change);
}

async function handleSaleSubmit(event) {
  event.preventDefault();
  if (!state.cart.length) {
    alert('Adicione ao menos um produto na venda.');
    return;
  }
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form).entries());
  const totals = calculateCartTotal();

  const insufficient = state.cart.find((item) => {
    const product = state.products.find((row) => row.id === item.id);
    return !product || Number(product.quantity) < Number(item.quantity);
  });
  if (insufficient) {
    alert(`Estoque insuficiente para ${insufficient.name}.`);
    return;
  }

  const payload = {
    customerName: values.customerName || '',
    paymentMethod: values.paymentMethod,
    discount: totals.discount,
    subtotal: totals.subtotal,
    total: totals.total,
    amountPaid: totals.amountPaid,
    change: totals.change,
    cashierId: state.currentUser.uid,
    cashierName: state.currentUser.fullName,
    items: state.cart.map((item) => ({ productId: item.id, name: item.name, quantity: item.quantity, unitPrice: item.salePrice, total: item.salePrice * item.quantity }))
  };

  await createDoc(refs.sales, payload);
  for (const item of state.cart) {
    const product = state.products.find((row) => row.id === item.id);
    await updateByPath('products', item.id, { quantity: Number(product.quantity) - Number(item.quantity) });
  }
  printReceipt(payload);
  state.cart = [];
  form.reset();
  renderSales();
}

function printReceipt(sale) {
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Cupom</title><style>body{font-family:monospace;padding:16px}table{width:100%;border-collapse:collapse}td,th{padding:4px 0;text-align:left}hr{border:none;border-top:1px dashed #000;margin:10px 0}</style></head><body>
    <div class="receipt">
      <h2>${escapeHtml(state.settings.storeName)}</h2>
      <p>${escapeHtml(state.settings.address)}</p>
      <hr>
      <p>CUPOM NÃO FISCAL</p>
      <p>Data: ${new Date().toLocaleString('pt-BR')}</p>
      <table><thead><tr><th>Item</th><th>Qtd</th><th>Unit.</th><th>Total</th></tr></thead><tbody>
        ${sale.items.map((item) => `<tr><td>${escapeHtml(item.name)}</td><td>${item.quantity}</td><td>${currency(item.unitPrice)}</td><td>${currency(item.total)}</td></tr>`).join('')}
      </tbody></table>
      <hr>
      <p>Total: ${currency(sale.total)}</p>
      <p>Forma de pagamento: ${escapeHtml(sale.paymentMethod)}</p>
      <p>Valor pago: ${currency(sale.amountPaid)}</p>
      <p>Troco: ${currency(sale.change)}</p>
      <hr>
      <p>${escapeHtml(state.settings.warrantyText)}</p>
    </div></body></html>`;
  const win = window.open('', '_blank');
  win.document.write(html);
  win.document.close();
  win.focus();
  win.print();
}

let streamRef = null;
let scanTimer = null;

async function startCameraScan() {
  const video = document.getElementById('barcode-video');
  if (!('BarcodeDetector' in window)) {
    alert('BarcodeDetector não disponível neste navegador. Use pesquisa manual ou um navegador compatível no celular.');
    return;
  }
  stopCameraScan();
  streamRef = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
  video.srcObject = streamRef;
  const detector = new BarcodeDetector({ formats: ['ean_13', 'ean_8', 'code_128', 'qr_code', 'upc_a', 'upc_e'] });

  scanTimer = window.setInterval(async () => {
    try {
      const codes = await detector.detect(video);
      if (!codes.length) return;
      const value = codes[0].rawValue;
      const match = state.products.find((item) => item.barcode === value);
      if (match) {
        addProductToCart(match.id);
        tabEls.sales.querySelector('#sale-product-search').value = value;
        stopCameraScan();
      }
    } catch (error) {
      console.error(error);
    }
  }, 850);
}

function stopCameraScan() {
  if (scanTimer) window.clearInterval(scanTimer);
  scanTimer = null;
  if (streamRef) streamRef.getTracks().forEach((track) => track.stop());
  streamRef = null;
}

function renderReports() {
  if (!hasPermission(state.currentUser, 'reports')) {
    tabEls.reports.innerHTML = renderBlocked();
    return;
  }
  const topSelling = getTopSelling(10);
  const lowSelling = getLowSelling(10);
  const lowStock = getLowStockProducts();
  const bySupplier = aggregateProducts('supplier');
  const byManufacturer = aggregateProducts('manufacturer');

  tabEls.reports.innerHTML = `
    <div class="cards-grid">
      <div class="card"><h3>Produtos em estoque</h3><strong>${state.products.filter((item) => item.status !== 'inativo').length}</strong><p class="muted">Cadastrados como ativos.</p></div>
      <div class="card"><h3>Quantidade em estoque</h3><strong>${state.products.reduce((sum, item) => sum + Number(item.quantity || 0), 0)}</strong><p class="muted">Soma total das unidades.</p></div>
      <div class="card"><h3>Estoque baixo</h3><strong>${lowStock.length}</strong><p class="muted">Abaixo do limite configurado.</p></div>
      <div class="card"><h3>Produtos vendidos</h3><strong>${state.sales.reduce((sum, sale) => sum + (sale.items?.length || 0), 0)}</strong><p class="muted">Itens em vendas registradas.</p></div>
    </div>
    <div class="grid-2" style="margin-top:18px;">
      <div class="table-card"><h3>Produtos com estoque baixo</h3>${reportTable(['Produto', 'Qtd', 'Fornecedor'], lowStock.map((item) => [item.name, item.quantity, item.supplier || '-']))}</div>
      <div class="table-card"><h3>Produtos mais vendidos</h3>${reportTable(['Produto', 'Qtd'], topSelling.map((item) => [item.name, item.qty]))}</div>
      <div class="table-card"><h3>Produtos com baixa saída</h3>${reportTable(['Produto', 'Qtd'], lowSelling.map((item) => [item.name, item.qty]))}</div>
      <div class="table-card"><h3>Relatório por fornecedor</h3>${reportTable(['Fornecedor', 'Qtd itens', 'Estoque'], bySupplier.map((item) => [item.label, item.products, item.qty]))}</div>
      <div class="table-card"><h3>Relatório por fabricante</h3>${reportTable(['Fabricante', 'Qtd itens', 'Estoque'], byManufacturer.map((item) => [item.label, item.products, item.qty]))}</div>
      <div class="table-card"><h3>Filtros combinados</h3>
        <form id="report-filter-form" class="form-grid">
          <label>Fornecedor<select name="supplier"><option value="">Todos</option>${uniqueOptions('supplier')}</select></label>
          <label>Fabricante<select name="manufacturer"><option value="">Todos</option>${uniqueOptions('manufacturer')}</select></label>
          <label>Status<select name="status"><option value="">Todos</option><option value="ativo">Ativo</option><option value="inativo">Inativo</option></select></label>
          <label>Texto livre<input name="term" placeholder="Nome, marca ou código" /></label>
          <div class="form-actions" style="grid-column:1 / -1;"><button class="btn btn-primary" type="submit">Aplicar</button></div>
        </form>
        <div id="combined-report-result" style="margin-top:14px;">${reportTable(['Produto', 'Fornecedor', 'Fabricante', 'Qtd'], state.products.slice(0, 8).map((item) => [item.name, item.supplier || '-', item.manufacturer || '-', item.quantity]))}</div>
      </div>
    </div>
  `;

  tabEls.reports.querySelector('#report-filter-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget).entries());
    const term = (values.term || '').toLowerCase();
    const filtered = state.products.filter((item) => {
      const haystack = [item.name, item.brand, item.barcode].join(' ').toLowerCase();
      return (!values.supplier || item.supplier === values.supplier)
        && (!values.manufacturer || item.manufacturer === values.manufacturer)
        && (!values.status || item.status === values.status)
        && (!term || haystack.includes(term));
    });
    tabEls.reports.querySelector('#combined-report-result').innerHTML = reportTable(['Produto', 'Fornecedor', 'Fabricante', 'Qtd'], filtered.map((item) => [item.name, item.supplier || '-', item.manufacturer || '-', item.quantity]));
  });
}

function reportTable(headers, rows) {
  return `<div class="table-wrap"><table><thead><tr>${headers.map((head) => `<th>${head}</th>`).join('')}</tr></thead><tbody>${rows.length ? rows.map((row) => `<tr>${row.map((col) => `<td>${escapeHtml(col)}</td>`).join('')}</tr>`).join('') : `<tr><td colspan="${headers.length}">Sem dados.</td></tr>`}</tbody></table></div>`;
}

function uniqueOptions(field) {
  return [...new Set(state.products.map((item) => item[field]).filter(Boolean))].sort().map((item) => `<option value="${escapeHtml(item)}">${escapeHtml(item)}</option>`).join('');
}

function aggregateProducts(field) {
  const map = new Map();
  state.products.forEach((item) => {
    const key = item[field] || 'Não informado';
    const current = map.get(key) || { label: key, products: 0, qty: 0 };
    current.products += 1;
    current.qty += Number(item.quantity || 0);
    map.set(key, current);
  });
  return [...map.values()].sort((a, b) => b.qty - a.qty);
}

function getTopSelling(limit = 5) {
  const map = new Map();
  state.sales.forEach((sale) => sale.items?.forEach((item) => map.set(item.name, (map.get(item.name) || 0) + Number(item.quantity || 0))));
  return [...map.entries()].map(([name, qty]) => ({ name, qty })).sort((a, b) => b.qty - a.qty).slice(0, limit);
}

function getLowSelling(limit = 5) {
  const sold = getTopSelling(9999);
  const soldMap = new Map(sold.map((item) => [item.name, item.qty]));
  return state.products.map((item) => ({ name: item.name, qty: soldMap.get(item.name) || 0 })).sort((a, b) => a.qty - b.qty).slice(0, limit);
}

function getLowStockProducts() {
  const threshold = Number(state.settings.lowStockThreshold || 5);
  return state.products.filter((item) => item.status !== 'inativo' && Number(item.quantity || 0) <= threshold);
}

function renderDeliveries() {
  if (!hasPermission(state.currentUser, 'deliveries')) {
    tabEls.deliveries.innerHTML = renderBlocked();
    return;
  }

  tabEls.deliveries.innerHTML = `
    <div class="deliveries-layout">
      <div class="panel">
        <div class="section-header"><h2>${state.editingDeliveryId ? 'Editar atendimento' : 'Agendar tele-entrega / recolhimento'}</h2></div>
        <form id="delivery-form" class="form-grid mobile-optimized">
          <label>Nome do cliente<input name="clientName" required /></label>
          <label>Telefone<input name="phone" required /></label>
          <label>Endereço<input name="address" required /></label>
          <label>Valor cobrado<input name="amount" type="number" step="0.01" min="0" value="0" /></label>
          <label>Forma de pagamento<select name="paymentMethod">${paymentMethods.map((item) => `<option value="${item}">${item}</option>`).join('')}</select></label>
          <label>Data<input name="date" type="date" required /></label>
          <label>Hora<input name="time" type="time" required /></label>
          <label>Status<select name="status">${deliveryStatuses.map((item) => `<option value="${item}">${item}</option>`).join('')}</select></label>
          <label style="grid-column:1 / -1;">Descrição<textarea name="description" required></textarea></label>
          <label style="grid-column:1 / -1;">Observações<textarea name="notes"></textarea></label>
          <div class="form-actions" style="grid-column:1 / -1;"><button class="btn btn-primary" type="submit">${state.editingDeliveryId ? 'Salvar' : 'Criar agendamento'}</button><button class="btn btn-secondary" id="delivery-reset-btn" type="button">Limpar</button></div>
        </form>
      </div>
      <div class="table-card">
        <div class="section-header"><h2>Agenda</h2></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Cliente</th><th>Data</th><th>Telefone</th><th>Status</th><th>Valor</th><th>Ações</th></tr></thead>
            <tbody>
              ${state.deliveries.map((item) => `<tr>
                <td>${escapeHtml(item.clientName)}</td>
                <td>${formatDate(item.scheduledAt)} ${item.time || ''}</td>
                <td>${escapeHtml(item.phone)}</td>
                <td><span class="tag ${deliveryStatusClass(item.status)}">${item.status}</span></td>
                <td>${currency(item.amount)}</td>
                <td><div class="inline-row"><button class="btn btn-secondary" data-delivery-edit="${item.id}">Editar</button><button class="btn btn-success" data-delivery-status="${item.id}:Concluído">Concluir</button><button class="btn btn-danger" data-delivery-status="${item.id}:Cancelado">Cancelar</button><button class="btn btn-secondary" data-delivery-status="${item.id}:Em rota">Iniciar</button><button class="btn btn-secondary" data-delivery-status="${item.id}:Reagendado">Reagendar</button></div></td>
              </tr>`).join('') || '<tr><td colspan="6">Nenhum atendimento cadastrado.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  const form = tabEls.deliveries.querySelector('#delivery-form');
  if (state.editingDeliveryId) {
    const editing = state.deliveries.find((item) => item.id === state.editingDeliveryId);
    if (editing) {
      form.elements.clientName.value = editing.clientName || '';
      form.elements.phone.value = editing.phone || '';
      form.elements.address.value = editing.address || '';
      form.elements.amount.value = editing.amount || 0;
      form.elements.paymentMethod.value = editing.paymentMethod || paymentMethods[0];
      form.elements.date.value = editing.date || '';
      form.elements.time.value = editing.time || '';
      form.elements.status.value = editing.status || deliveryStatuses[0];
      form.elements.description.value = editing.description || '';
      form.elements.notes.value = editing.notes || '';
    }
  }

  form.addEventListener('submit', handleDeliverySubmit);
  tabEls.deliveries.querySelector('#delivery-reset-btn').addEventListener('click', () => { state.editingDeliveryId = null; renderDeliveries(); });
  tabEls.deliveries.querySelectorAll('[data-delivery-edit]').forEach((btn) => btn.addEventListener('click', () => { state.editingDeliveryId = btn.dataset.deliveryEdit; renderDeliveries(); }));
  tabEls.deliveries.querySelectorAll('[data-delivery-status]').forEach((btn) => btn.addEventListener('click', async () => {
    const [id, status] = btn.dataset.deliveryStatus.split(':');
    await updateByPath('deliveries', id, { status });
  }));
}

function deliveryStatusClass(status) {
  if (status === 'Concluído') return 'success';
  if (status === 'Cancelado') return 'danger';
  if (status === 'Reagendado') return 'warning';
  return 'info';
}

async function handleDeliverySubmit(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.currentTarget).entries());
  data.amount = toNumber(data.amount);
  data.scheduledAt = timestampFromDateTime(data.date, data.time);
  data.assignedUserId = state.currentUser.uid;
  data.assignedUserName = state.currentUser.fullName;

  if (state.editingDeliveryId) {
    await updateByPath('deliveries', state.editingDeliveryId, data);
    state.editingDeliveryId = null;
  } else {
    await createDoc(refs.deliveries, data);
  }
  event.currentTarget.reset();
}

function renderUsers() {
  if (!hasPermission(state.currentUser, 'users')) {
    tabEls.users.innerHTML = renderBlocked();
    return;
  }

  tabEls.users.innerHTML = `
    <div class="users-layout">
      <div class="panel">
        <div class="section-header"><h2>${state.editingUserId ? 'Editar usuário' : 'Cadastrar usuário'}</h2></div>
        <form id="user-form" class="form-grid">
          <label>Nome completo<input name="fullName" required /></label>
          <label>Usuário<input name="username" required /></label>
          <label>Senha<input name="password" type="password" ${state.editingUserId ? '' : 'required'} /></label>
          <label>Função<select name="role">${ROLES.map((role) => `<option value="${role}">${role}</option>`).join('')}</select></label>
          <label>Status<select name="active"><option value="true">Ativo</option><option value="false">Inativo</option></select></label>
          <div style="grid-column:1 / -1;">
            <p class="muted">Áreas liberadas</p>
            <div class="permission-grid">${AREAS.map((area) => `<label class="permission-item"><input type="checkbox" name="permissions" value="${area}"> ${labelTab(area)}</label>`).join('')}</div>
          </div>
          <div class="form-actions" style="grid-column:1 / -1;"><button class="btn btn-primary" type="submit">${state.editingUserId ? 'Salvar usuário' : 'Cadastrar usuário'}</button><button type="button" id="user-reset-btn" class="btn btn-secondary">Limpar</button></div>
        </form>
      </div>
      <div class="table-card">
        <div class="section-header"><h2>Usuários</h2></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Nome</th><th>Usuário</th><th>Função</th><th>Status</th><th>Permissões</th><th>Ações</th></tr></thead>
            <tbody>
              ${state.users.map((user) => `<tr><td>${escapeHtml(user.fullName)}</td><td>${escapeHtml(user.username)}</td><td>${escapeHtml(user.role)}</td><td><span class="tag ${user.active ? 'success' : 'warning'}">${user.active ? 'Ativo' : 'Inativo'}</span></td><td>${(user.permissions || []).map(labelTab).join(', ')}</td><td><div class="inline-row"><button class="btn btn-secondary" data-user-edit="${user.id}">Editar</button><button class="btn btn-danger" data-user-delete="${user.id}">Excluir lógico</button></div></td></tr>`).join('') || '<tr><td colspan="6">Nenhum usuário cadastrado.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  const form = tabEls.users.querySelector('#user-form');
  const roleField = form.elements.role;
  roleField.addEventListener('change', () => markPermissionCheckboxes(form, ensurePermissionsByRole(roleField.value)));

  if (state.editingUserId) {
    const editing = state.users.find((item) => item.id === state.editingUserId);
    if (editing) {
      form.elements.fullName.value = editing.fullName || '';
      form.elements.username.value = editing.username || '';
      form.elements.role.value = editing.role || 'Vendedor';
      form.elements.active.value = String(Boolean(editing.active));
      markPermissionCheckboxes(form, editing.permissions || []);
    }
  } else {
    markPermissionCheckboxes(form, ensurePermissionsByRole(roleField.value));
  }

  form.addEventListener('submit', handleUserSubmit);
  tabEls.users.querySelector('#user-reset-btn').addEventListener('click', () => { state.editingUserId = null; renderUsers(); });
  tabEls.users.querySelectorAll('[data-user-edit]').forEach((btn) => btn.addEventListener('click', () => { state.editingUserId = btn.dataset.userEdit; renderUsers(); }));
  tabEls.users.querySelectorAll('[data-user-delete]').forEach((btn) => btn.addEventListener('click', async () => {
    await deleteManagedUser(state.currentUser, btn.dataset.userDelete);
    state.users = await listUsers();
    renderUsers();
  }));
}

function markPermissionCheckboxes(form, permissions) {
  [...form.querySelectorAll('input[name="permissions"]')].forEach((input) => { input.checked = permissions.includes(input.value); });
}

async function handleUserSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const raw = Object.fromEntries(new FormData(form).entries());
  const permissions = [...form.querySelectorAll('input[name="permissions"]:checked')].map((input) => input.value);
  const payload = { ...raw, permissions, active: raw.active === 'true' };

  if (state.editingUserId) await updateManagedUser(state.currentUser, state.editingUserId, payload);
  else await createManagedUser(state.currentUser, payload);

  state.editingUserId = null;
  state.users = await listUsers();
  form.reset();
  renderUsers();
}

function renderSettings() {
  if (!hasPermission(state.currentUser, 'settings')) {
    tabEls.settings.innerHTML = renderBlocked();
    return;
  }

  tabEls.settings.innerHTML = `
    <div class="settings-layout">
      <div class="panel">
        <div class="section-header"><h2>Configurações gerais</h2></div>
        <form id="settings-form" class="settings-grid">
          <label>Nome da loja<input name="storeName" value="${escapeHtml(state.settings.storeName || '')}" /></label>
          <label>Endereço<input name="address" value="${escapeHtml(state.settings.address || '')}" /></label>
          <label>Limite de estoque baixo<input name="lowStockThreshold" type="number" min="1" value="${state.settings.lowStockThreshold || 5}" /></label>
          <label>Texto de garantia<textarea name="warrantyText">${escapeHtml(state.settings.warrantyText || '')}</textarea></label>
          <div class="form-actions"><button class="btn btn-primary" type="submit">Salvar configurações</button></div>
        </form>
      </div>
      <div class="panel">
        <div class="section-header"><h2>Segurança</h2></div>
        <form id="password-form" class="settings-grid">
          <label>Nova senha<input name="password" type="password" required /></label>
          <div class="form-actions"><button class="btn btn-secondary" type="submit">Trocar senha</button></div>
        </form>
        <div class="auth-hint" style="margin-top:16px;">Usuários inativos não conseguem entrar, mesmo com senha correta. As permissões são conferidas tanto na interface quanto nas regras do Firestore.</div>
      </div>
    </div>
  `;

  tabEls.settings.querySelector('#settings-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    payload.lowStockThreshold = Number(payload.lowStockThreshold || 5);
    const existing = (await listCollection('settings')).find((item) => item.scope === 'system');
    if (existing) await updateByPath('settings', existing.id, { ...payload, scope: 'system' });
    else await createDoc(refs.settings, { ...payload, scope: 'system' });
  });

  tabEls.settings.querySelector('#password-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const value = new FormData(event.currentTarget).get('password');
    await changeCurrentPassword(String(value));
    event.currentTarget.reset();
    alert('Senha atualizada com sucesso.');
  });
}

function renderStockAlerts() {
  const lowStock = getLowStockProducts();
  els.stockAlertCount.textContent = String(lowStock.length);
  els.stockAlertList.innerHTML = lowStock.map((item) => `<div class="alert-item"><strong>${escapeHtml(item.name)}</strong><span>Estoque atual: ${item.quantity}</span></div>`).join('') || '<div class="empty-state">Sem alertas no momento.</div>';
}

function labelTab(tab) {
  return { dashboard: 'Dashboard', sales: 'Vendas', products: 'Produtos', reports: 'Relatórios', deliveries: 'Tele-entregas', users: 'Usuários', settings: 'Configurações' }[tab] || tab;
}

function renderBlocked() {
  return '<div class="card"><h2>Acesso restrito</h2><p class="muted">Seu usuário não possui permissão para acessar esta área.</p></div>';
}

els.loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  showFeedback('Entrando...');
  try {
    await login(els.loginIdentifier.value, els.loginPassword.value);
    showFeedback('Login realizado.', 'success');
  } catch (error) {
    console.error(error);
    showFeedback(error.message || 'Falha ao autenticar.', 'error');
  }
});

els.logoutBtn.addEventListener('click', async () => { await logout(); stopCameraScan(); });
els.nav.addEventListener('click', (event) => {
  const button = event.target.closest('[data-tab]');
  if (!button) return;
  activateTab(button.dataset.tab);
});
els.stockAlertBtn.addEventListener('click', () => els.stockAlertPanel.classList.toggle('hidden'));
els.mobileMenuBtn.addEventListener('click', () => document.querySelector('.sidebar')?.classList.toggle('open'));
document.addEventListener('click', (event) => {
  if (!event.target.closest('.alert-wrapper')) els.stockAlertPanel.classList.add('hidden');
});

watchAuth(async (user) => {
  state.currentUser = user;
  if (!user) {
    setMainView(false);
    return;
  }
  setMainView(true);
  els.userName.textContent = user.fullName || user.username || user.email;
  els.userRole.textContent = `${formatRole(user.role)} · ${user.active ? 'Ativo' : 'Inativo'}`;
  activateTab(hasPermission(user, 'dashboard') ? 'dashboard' : (AREAS.find((area) => hasPermission(user, area)) || 'deliveries'));
  await bootstrapData();
  renderApp();
  bindCartButtons();
});
