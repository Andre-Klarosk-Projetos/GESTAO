import {
  createUserWithEmailAndPassword,
  EmailAuthProvider,
  onAuthStateChanged,
  reauthenticateWithCredential,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  signOut,
  updatePassword,
  getAuth
} from "https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js";

import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  orderBy as firestoreOrderBy,
  query,
  serverTimestamp,
  setDoc,
  updateDoc
} from "https://www.gstatic.com/firebasejs/10.12.5/firebase-firestore.js";

import {
  initializeApp,
  deleteApp
} from "https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js";

import { auth, db, firebaseConfig } from "../firebase-config.js";

const APP_TO_DB_AREA = {
  dashboard: "dashboard",
  sales: "vendas",
  products: "produtos",
  reports: "relatorios",
  deliveries: "tele_entregas",
  users: "usuarios",
  settings: "configuracoes"
};

const DB_TO_APP_AREA = {
  dashboard: "dashboard",
  vendas: "sales",
  produtos: "products",
  relatorios: "reports",
  tele_entregas: "deliveries",
  usuarios: "users",
  configuracoes: "settings",
  estoque: "products"
};

function isObject(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

function sanitizeString(value) {
  return String(value ?? "").trim();
}

function normalizeRole(role) {
  const value = sanitizeString(role);

  if (value === "Administrador") return "Administrador";
  if (value === "Gerente") return "Gerente";
  if (value === "Vendedor") return "Vendedor";
  if (value === "Estoque") return "Estoque";
  if (value === "Entregador") return "Entregador";

  return "Vendedor";
}

export function normalizeLoginEmail(value) {
  const input = sanitizeString(value).toLowerCase();

  if (!input) return "";
  if (input.includes("@")) return input;

  return `${input}@gestao.local`;
}

function roleIsAdmin(role) {
  const normalized = normalizeRole(role);
  return normalized === "Administrador" || normalized === "Gerente";
}

function permissionsArrayToMap(permissions = [], role = "Vendedor") {
  const map = {
    dashboard: false,
    vendas: false,
    produtos: false,
    relatorios: false,
    tele_entregas: false,
    usuarios: false,
    configuracoes: false,
    estoque: false
  };

  if (Array.isArray(permissions)) {
    permissions.forEach((item) => {
      const dbKey = APP_TO_DB_AREA[item];
      if (dbKey) {
        map[dbKey] = true;
      }
    });
  }

  if (roleIsAdmin(role)) {
    Object.keys(map).forEach((key) => {
      map[key] = true;
    });
  } else if (normalizeRole(role) === "Vendedor") {
    map.vendas = true;
    map.produtos = true;
    map.tele_entregas = true;
    map.estoque = true;
  } else if (normalizeRole(role) === "Estoque") {
    map.produtos = true;
    map.estoque = true;
  } else if (normalizeRole(role) === "Entregador") {
    map.tele_entregas = true;
  }

  return map;
}

function permissionsMapToArray(permissoes = {}) {
  const result = new Set();

  Object.entries(permissoes || {}).forEach(([key, value]) => {
    if (value === true && DB_TO_APP_AREA[key]) {
      result.add(DB_TO_APP_AREA[key]);
    }
  });

  return [...result];
}

function firestoreUserToAppUser(uid, data = {}) {
  const isLegacy = data.fullName !== undefined || data.role !== undefined || data.active !== undefined;

  const fullName = isLegacy ? (data.fullName || "") : (data.nome || "");
  const username = isLegacy ? (data.username || "") : (data.usuario || "");
  const email = data.email || "";

  const role = isLegacy
    ? normalizeRole(data.role || "Vendedor")
    : normalizeRole(data.tipo || "Vendedor");

  const active = isLegacy
    ? data.active === true
    : data.ativo === true;

  const deleted = data.deleted === true;

  const permissions = isLegacy
    ? (Array.isArray(data.permissions) ? data.permissions : [])
    : permissionsMapToArray(data.permissoes || {});

  const permissionsMap = isLegacy
    ? permissionsArrayToMap(permissions, role)
    : { ...(data.permissoes || {}) };

  return {
    id: uid,
    uid,
    fullName,
    username,
    email,
    role,
    active,
    deleted,
    permissions,
    permissionsMap,
    rawProfile: data
  };
}

function appPayloadToFirestorePayload(data = {}, mode = "create") {
  const role = normalizeRole(data.role || data.tipo || "Vendedor");
  const permissionsArray = Array.isArray(data.permissions) ? data.permissions : [];
  const permissionsMap = isObject(data.permissoes)
    ? data.permissoes
    : permissionsArrayToMap(permissionsArray, role);

  const payload = {
    nome: sanitizeString(data.fullName || data.nome),
    usuario: sanitizeString(data.username || data.usuario).toLowerCase(),
    email: normalizeLoginEmail(data.email || data.username || data.usuario),
    tipo: role,
    ativo: data.active === undefined ? (data.ativo !== false) : data.active === true,
    permissoes: permissionsMap,
    fullName: sanitizeString(data.fullName || data.nome),
    username: sanitizeString(data.username || data.usuario).toLowerCase(),
    role: role,
    active: data.active === undefined ? (data.ativo !== false) : data.active === true,
    permissions: Array.isArray(data.permissions) ? data.permissions : permissionsMapToArray(permissionsMap),
    updatedAt: serverTimestamp()
  };

  if (mode === "create") {
    payload.createdAt = serverTimestamp();
    payload.deleted = false;
  }

  return payload;
}

function buildFriendlyAuthError(error) {
  const code = error?.code || "";

  switch (code) {
    case "auth/invalid-credential":
    case "auth/wrong-password":
    case "auth/user-not-found":
    case "auth/invalid-login-credentials":
      return new Error("Usuário ou senha inválidos.");

    case "auth/invalid-email":
      return new Error("E-mail inválido.");

    case "auth/email-already-in-use":
      return new Error("Este e-mail já está em uso.");

    case "auth/weak-password":
      return new Error("A senha precisa ter pelo menos 6 caracteres.");

    case "auth/too-many-requests":
      return new Error("Tente novamente em instantes.");

    case "auth/requires-recent-login":
      return new Error("Por segurança, faça login novamente antes de alterar a senha.");

    case "permission-denied":
      return new Error("Sem permissão para acessar os dados no Firestore.");

    default:
      return error instanceof Error
        ? error
        : new Error("Ocorreu um erro inesperado na autenticação.");
  }
}

async function getUserDocByUid(uid) {
  if (!uid) {
    throw new Error("UID do usuário não informado.");
  }

  const ref = doc(db, "users", uid);
  const snap = await getDoc(ref);
  return { ref, snap };
}

function parseCreateArgs(arg1, arg2) {
  if (arg2 !== undefined) {
    return { actor: arg1, data: arg2 };
  }

  return { actor: null, data: arg1 };
}

function parseUpdateArgs(arg1, arg2, arg3) {
  if (arg3 !== undefined) {
    return { actor: arg1, uid: arg2, data: arg3 };
  }

  return { actor: null, uid: arg1, data: arg2 };
}

function parseDeleteArgs(arg1, arg2) {
  if (arg2 !== undefined) {
    return { actor: arg1, uid: arg2 };
  }

  return { actor: null, uid: arg1 };
}

async function createSecondaryAppAndAuth() {
  const appName = `user-creator-${Date.now()}`;
  const secondaryApp = initializeApp(firebaseConfig, appName);
  const secondaryAuth = getAuth(secondaryApp);

  return { secondaryApp, secondaryAuth };
}

async function destroySecondaryApp(appInstance) {
  if (!appInstance) return;

  try {
    await deleteApp(appInstance);
  } catch (error) {
    console.warn("Não foi possível destruir o app secundário:", error);
  }
}

export async function login(identifier, password) {
  try {
    const loginEmail = normalizeLoginEmail(identifier);

    if (!loginEmail) {
      throw new Error("Informe o usuário ou e-mail.");
    }

    if (!password) {
      throw new Error("Informe a senha.");
    }

    const credential = await signInWithEmailAndPassword(auth, loginEmail, password);
    const authUser = credential.user;
    const { snap } = await getUserDocByUid(authUser.uid);

    if (!snap.exists()) {
      await signOut(auth);
      throw new Error("Perfil do usuário não encontrado no Firestore. Crie o documento na coleção users usando o UID do Authentication.");
    }

    const user = firestoreUserToAppUser(authUser.uid, snap.data());

    if (user.deleted === true) {
      await signOut(auth);
      throw new Error("Usuário excluído logicamente. Acesso bloqueado.");
    }

    if (user.active !== true) {
      await signOut(auth);
      throw new Error("Usuário inativo. Acesso bloqueado.");
    }

    return user;
  } catch (error) {
    console.error("Erro no login:", error);
    throw buildFriendlyAuthError(error);
  }
}

export async function logout() {
  await signOut(auth);
}

export const logoutUser = logout;

export function getCurrentAuthUser() {
  return auth.currentUser || null;
}

export async function getCurrentUserProfile() {
  const currentUser = auth.currentUser;

  if (!currentUser) {
    return null;
  }

  const { snap } = await getUserDocByUid(currentUser.uid);

  if (!snap.exists()) {
    return null;
  }

  return firestoreUserToAppUser(currentUser.uid, snap.data());
}

export function watchAuth(callback) {
  return onAuthStateChanged(auth, async (firebaseUser) => {
    try {
      if (!firebaseUser) {
        callback(null);
        return;
      }

      const { snap } = await getUserDocByUid(firebaseUser.uid);

      if (!snap.exists()) {
        await signOut(auth);
        callback(null);
        return;
      }

      const user = firestoreUserToAppUser(firebaseUser.uid, snap.data());

      if (user.deleted === true || user.active !== true) {
        await signOut(auth);
        callback(null);
        return;
      }

      callback(user);
    } catch (error) {
      console.error("Erro ao carregar sessão:", error);
      callback(null);
    }
  });
}

export const onUserSession = watchAuth;

export async function changePassword(currentPassword, newPassword) {
  const user = auth.currentUser;

  if (!user) {
    throw new Error("Nenhum usuário autenticado.");
  }

  if (!newPassword || String(newPassword).trim().length < 6) {
    throw new Error("A nova senha precisa ter pelo menos 6 caracteres.");
  }

  try {
    if (currentPassword && String(currentPassword).trim()) {
      const credential = EmailAuthProvider.credential(user.email, currentPassword);
      await reauthenticateWithCredential(user, credential);
    }

    await updatePassword(user, newPassword);
    return true;
  } catch (error) {
    console.error("Erro ao trocar senha:", error);
    throw buildFriendlyAuthError(error);
  }
}

export async function changeCurrentPassword(currentPassword, newPassword) {
  if (newPassword === undefined) {
    return changePassword("", currentPassword);
  }

  return changePassword(currentPassword, newPassword);
}

export async function sendResetPassword(email) {
  const normalizedEmail = normalizeLoginEmail(email);

  if (!normalizedEmail) {
    throw new Error("Informe um e-mail válido.");
  }

  try {
    await sendPasswordResetEmail(auth, normalizedEmail);
    return true;
  } catch (error) {
    console.error("Erro ao enviar redefinição de senha:", error);
    throw buildFriendlyAuthError(error);
  }
}

export const forgotPassword = sendResetPassword;

export async function createManagedUser(arg1, arg2) {
  const { data } = parseCreateArgs(arg1, arg2);

  const fullName = sanitizeString(data?.fullName || data?.nome);
  const username = sanitizeString(data?.username || data?.usuario).toLowerCase();
  const password = sanitizeString(data?.password || data?.senha);
  const email = normalizeLoginEmail(data?.email || username);

  if (!fullName) {
    throw new Error("Informe o nome completo.");
  }

  if (!username) {
    throw new Error("Informe o usuário.");
  }

  if (!password || password.length < 6) {
    throw new Error("A senha precisa ter pelo menos 6 caracteres.");
  }

  if (!email) {
    throw new Error("Informe um e-mail válido.");
  }

  let secondaryApp = null;
  let secondaryAuth = null;

  try {
    ({ secondaryApp, secondaryAuth } = await createSecondaryAppAndAuth());

    const credential = await createUserWithEmailAndPassword(secondaryAuth, email, password);
    const createdUser = credential.user;

    const payload = appPayloadToFirestorePayload(
      {
        ...data,
        fullName,
        username,
        email
      },
      "create"
    );

    await setDoc(doc(db, "users", createdUser.uid), payload);
    await signOut(secondaryAuth);

    return firestoreUserToAppUser(createdUser.uid, payload);
  } catch (error) {
    console.error("Erro ao criar usuário:", error);
    throw buildFriendlyAuthError(error);
  } finally {
    await destroySecondaryApp(secondaryApp);
  }
}

export const createUser = createManagedUser;

export async function updateManagedUser(arg1, arg2, arg3) {
  const { uid, data } = parseUpdateArgs(arg1, arg2, arg3);

  if (!uid) {
    throw new Error("UID do usuário não informado.");
  }

  const updates = appPayloadToFirestorePayload(data || {}, "update");

  if (!sanitizeString(data?.fullName || data?.nome)) delete updates.nome;
  if (!sanitizeString(data?.username || data?.usuario)) delete updates.usuario;
  if (!sanitizeString(data?.email)) delete updates.email;
  if (!sanitizeString(data?.role || data?.tipo)) delete updates.tipo;
  if (!sanitizeString(data?.fullName || data?.nome)) delete updates.fullName;
  if (!sanitizeString(data?.username || data?.usuario)) delete updates.username;
  if (!sanitizeString(data?.role || data?.tipo)) delete updates.role;

  if (!Array.isArray(data?.permissions) && !isObject(data?.permissoes)) {
    delete updates.permissoes;
    delete updates.permissions;
  }

  if (typeof data?.active !== "boolean" && typeof data?.ativo !== "boolean") {
    delete updates.ativo;
    delete updates.active;
  }

  await updateDoc(doc(db, "users", uid), updates);
  return true;
}

export const updateUser = updateManagedUser;

export async function setUserActiveStatus(uid, ativo) {
  if (!uid) {
    throw new Error("UID do usuário não informado.");
  }

  await updateDoc(doc(db, "users", uid), {
    ativo: ativo === true,
    active: ativo === true,
    updatedAt: serverTimestamp()
  });

  return true;
}

export const toggleUserStatus = setUserActiveStatus;

export async function softDeleteManagedUser(arg1, arg2) {
  const { uid } = parseDeleteArgs(arg1, arg2);

  if (!uid) {
    throw new Error("UID do usuário não informado.");
  }

  await updateDoc(doc(db, "users", uid), {
    ativo: false,
    active: false,
    deleted: true,
    updatedAt: serverTimestamp()
  });

  return true;
}

export const deleteManagedUser = softDeleteManagedUser;
export const deleteUserSoft = softDeleteManagedUser;

export async function hardDeleteUserDoc(uid) {
  if (!uid) {
    throw new Error("UID do usuário não informado.");
  }

  await deleteDoc(doc(db, "users", uid));
  return true;
}

export async function listUsers() {
  const usersRef = collection(db, "users");
  const usersQuery = query(usersRef, firestoreOrderBy("updatedAt", "desc"));
  const snap = await getDocs(usersQuery);

  return snap.docs
    .map((item) => firestoreUserToAppUser(item.id, item.data()))
    .filter((item) => item.deleted !== true);
}

export function hasPermission(profile, area) {
  if (!profile || !area) return false;

  if (roleIsAdmin(profile.role || profile.tipo)) {
    return true;
  }

  const permissions = Array.isArray(profile.permissions)
    ? profile.permissions
    : permissionsMapToArray(profile.permissoes || {});

  return permissions.includes(area);
}

export function isUserActive(profile) {
  return profile?.active === true || profile?.ativo === true;
}

export function isAdmin(profile) {
  return roleIsAdmin(profile?.role || profile?.tipo) && isUserActive(profile);
}