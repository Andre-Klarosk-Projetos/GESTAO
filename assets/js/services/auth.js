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

  if (value === "Administrador") return "Gerente";
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

  const normalizedRole = normalizeRole(role);

  if (normalizedRole === "Gerente") {
    Object.keys(map).forEach((key) => {
      map[key] = true;
    });
  }

  if (normalizedRole === "Vendedor") {
    map.vendas = true;
    map.produtos = true;
    map.tele_entregas = true;
    map.estoque = true;
  }

  if (normalizedRole === "Estoque") {
    map.produtos = true;
    map.estoque = true;
  }

  if (normalizedRole === "Entregador") {
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
  const permissions = permissionsMapToArray(data.permissoes || {});

  return {
    id: uid,
    uid,
    fullName: data.nome || "",
    username: data.usuario || "",
    email: data.email || "",
    role: normalizeRole(data.tipo),
    active: data.ativo === true,
    deleted: data.deleted === true,
    permissions,
    permissionsMap: { ...(data.permissoes || {}) },
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
      return new Error("Muitas tentativas. Tente novamente em instantes.");

    case "auth/requires-recent-login":
      return new Error("Por segurança, informe a senha atual para definir a nova senha.");

    case "permission-denied":
      return new Error("Sem permissão para acessar os dados no Firestore.");

    default:
      return error instanceof Error
        ? error
        : new Error("Ocorreu um erro inesperado na autenticação.");
  }
}

async function getUserSnapshotByUid(uid) {
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
    const { snap } = await getUserSnapshotByUid(authUser.uid);

    if (!snap.exists()) {
      await signOut(auth);
      throw new Error("Perfil do usuário não encontrado no Firestore. Crie o documento na coleção users com o UID do Authentication.");
    }

    const data = snap.data();

    if (data.deleted === true) {
      await signOut(auth);
      throw new Error("Usuário excluído logicamente. Acesso bloqueado.");
    }

    if (data.ativo !== true) {
      await signOut(auth);
      throw new Error("Usuário inativo. Acesso bloqueado.");
    }

    return firestoreUserToAppUser(authUser.uid, data);
  } catch (error) {
    console.error("Erro no login:", error);
    throw buildFriendlyAuthError(error);
  }
}

export async function logout() {
  await signOut(auth);
}

export async function logoutUser() {
  await signOut(auth);
}

export function getCurrentAuthUser() {
  return auth.currentUser || null;
}

export async function getCurrentUserProfile() {
  const currentUser = auth.currentUser;

  if (!currentUser) {
    return null;
  }

  const { snap } = await getUserSnapshotByUid(currentUser.uid);

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

      const { snap } = await getUserSnapshotByUid(firebaseUser.uid);

      if (!snap.exists()) {
        await signOut(auth);
        callback(null);
        return;
      }

      const data = snap.data();

      if (data.deleted === true || data.ativo !== true) {
        await signOut(auth);
        callback(null);
        return;
      }

      callback(firestoreUserToAppUser(firebaseUser.uid, data));
    } catch (error) {
      console.error("Erro ao observar autenticação:", error);
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
    const secondary = await createSecondaryAppAndAuth();
    secondaryApp = secondary.secondaryApp;
    secondaryAuth = secondary.secondaryAuth;

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

  const payload = appPayloadToFirestorePayload(data || {}, "update");

  if (!sanitizeString(data?.fullName || data?.nome)) {
    delete payload.nome;
  }

  if (!sanitizeString(data?.username || data?.usuario)) {
    delete payload.usuario;
  }

  if (!sanitizeString(data?.email)) {
    delete payload.email;
  }

  if (!sanitizeString(data?.role || data?.tipo)) {
    delete payload.tipo;
  }

  if (!Array.isArray(data?.permissions) && !isObject(data?.permissoes)) {
    delete payload.permissoes;
  }

  if (typeof data?.active !== "boolean" && typeof data?.ativo !== "boolean") {
    delete payload.ativo;
  }

  await updateDoc(doc(db, "users", uid), payload);
  return true;
}

export const updateUser = updateManagedUser;

export async function setUserActiveStatus(uid, active) {
  if (!uid) {
    throw new Error("UID do usuário não informado.");
  }

  await updateDoc(doc(db, "users", uid), {
    ativo: active === true,
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
  const usersQuery = query(usersRef, firestoreOrderBy("nome"));
  const snap = await getDocs(usersQuery);

  return snap.docs
    .map((item) => firestoreUserToAppUser(item.id, item.data()))
    .filter((item) => item.deleted !== true);
}

export function hasPermission(profile, area) {
  if (!profile || !area) return false;

  if (normalizeRole(profile.role || profile.tipo) === "Gerente") {
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
  return normalizeRole(profile?.role || profile?.tipo) === "Gerente" && isUserActive(profile);
}