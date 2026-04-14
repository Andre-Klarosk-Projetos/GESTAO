export const AREAS = ['dashboard', 'sales', 'products', 'reports', 'deliveries', 'users', 'settings'];
export const ROLES = ['Administrador', 'Gerente', 'Vendedor', 'Estoque', 'Entregador'];
export const DEFAULT_PERMISSIONS = {
  Administrador: [...AREAS],
  Gerente: ['dashboard', 'sales', 'products', 'reports', 'deliveries'],
  Vendedor: ['dashboard', 'sales', 'products', 'deliveries'],
  Estoque: ['dashboard', 'products', 'reports'],
  Entregador: ['deliveries']
};

export const paymentMethods = ['Dinheiro', 'PIX', 'Cartão de Débito', 'Cartão de Crédito', 'Boleto'];
export const deliveryStatuses = ['Agendado', 'Em rota', 'Concluído', 'Cancelado', 'Reagendado', 'Recolhimento'];

export function sanitizeUsername(value = '') {
  return value.toLowerCase().trim().replace(/[^a-z0-9._-]/g, '');
}

export function usernameToEmail(username = '') {
  const clean = sanitizeUsername(username);
  return clean.includes('@') ? clean : `${clean}@gestao.local`;
}

export function currency(value = 0) {
  return Number(value || 0).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
}

export function toNumber(value) {
  return Number(String(value ?? '').replace(',', '.')) || 0;
}

export function formatDate(value) {
  if (!value) return '-';
  const date = typeof value?.toDate === 'function' ? value.toDate() : new Date(value);
  return date.toLocaleDateString('pt-BR');
}

export function formatDateTime(value) {
  if (!value) return '-';
  const date = typeof value?.toDate === 'function' ? value.toDate() : new Date(value);
  return date.toLocaleString('pt-BR');
}

export function formatRole(role) {
  return role || 'Sem função';
}

export function hasPermission(user, area) {
  if (!user) return false;
  if (user.role === 'Administrador') return true;
  return Array.isArray(user.permissions) && user.permissions.includes(area);
}

export function ensurePermissionsByRole(role) {
  return DEFAULT_PERMISSIONS[role] ? [...DEFAULT_PERMISSIONS[role]] : ['dashboard'];
}

export function downloadHtml(filename, html) {
  const blob = new Blob([html], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function uid() {
  return crypto.randomUUID();
}
