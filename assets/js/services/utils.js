export const AREAS = [
  "dashboard",
  "sales",
  "products",
  "reports",
  "deliveries",
  "users",
  "settings"
];

export const ROLES = [
  "Gerente",
  "Vendedor",
  "Estoque",
  "Entregador"
];

export const paymentMethods = [
  "Dinheiro",
  "PIX",
  "Cartão de Débito",
  "Cartão de Crédito",
  "Boleto"
];

export const deliveryStatuses = [
  "Agendado",
  "Em rota",
  "Reagendado",
  "Concluído",
  "Cancelado",
  "Recolhimento"
];

export function currency(value) {
  return Number(value || 0).toLocaleString("pt-BR", {
    style: "currency",
    currency: "BRL"
  });
}

export function toNumber(value) {
  if (value === null || value === undefined || value === "") {
    return 0;
  }

  const normalized = String(value).replace(/\./g, "").replace(",", ".");
  const number = Number(normalized);

  return Number.isFinite(number) ? number : 0;
}

export function formatDate(value) {
  if (!value) return "-";

  const date = value?.toDate ? value.toDate() : new Date(value);

  if (Number.isNaN(date.getTime())) return "-";

  return date.toLocaleDateString("pt-BR");
}

export function formatDateTime(value) {
  if (!value) return "-";

  const date = value?.toDate ? value.toDate() : new Date(value);

  if (Number.isNaN(date.getTime())) return "-";

  return date.toLocaleString("pt-BR");
}

export function formatRole(role) {
  if (!role) return "-";
  return role;
}

export function hasPermission(user, area) {
  if (!user || !area) return false;

  if (user.role === "Gerente" || user.role === "Administrador") {
    return true;
  }

  const permissions = Array.isArray(user.permissions) ? user.permissions : [];
  return permissions.includes(area);
}

export function ensurePermissionsByRole(role) {
  if (role === "Gerente" || role === "Administrador") {
    return [...AREAS];
  }

  if (role === "Vendedor") {
    return ["sales", "products", "deliveries"];
  }

  if (role === "Estoque") {
    return ["products"];
  }

  if (role === "Entregador") {
    return ["deliveries"];
  }

  return [];
}