import {
  signInWithEmailAndPassword,
  onAuthStateChanged,
  signOut,
  updatePassword,
  createUserWithEmailAndPassword,
  getAuth
} from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js';
import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js';
import { auth, firebaseConfig } from '../firebase-config.js';
import { getByPath, listCollection, where, query, getDocs, refs, createDocWithId, updateByPath } from './db.js';
import { sanitizeUsername, usernameToEmail, ensurePermissionsByRole } from './utils.js';

export async function login(identifier, password) {
  const normalized = identifier.includes('@') ? identifier.trim() : usernameToEmail(identifier);
  const credential = await signInWithEmailAndPassword(auth, normalized, password);
  const profileSnap = await getByPath('users', credential.user.uid);

  if (!profileSnap.exists()) {
    await signOut(auth);
    throw new Error('Usuário autenticado, mas sem cadastro no Firestore.');
  }

  const profile = profileSnap.data();
  if (!profile.active) {
    await signOut(auth);
    throw new Error('Usuário inativo. Acesso bloqueado.');
  }

  return { uid: credential.user.uid, email: credential.user.email, ...profile };
}

export function watchAuth(callback) {
  return onAuthStateChanged(auth, async (firebaseUser) => {
    if (!firebaseUser) {
      callback(null);
      return;
    }

    const profileSnap = await getByPath('users', firebaseUser.uid);
    if (!profileSnap.exists()) {
      callback(null);
      return;
    }

    const profile = profileSnap.data();
    if (!profile.active) {
      await signOut(auth);
      callback(null);
      return;
    }

    callback({ uid: firebaseUser.uid, email: firebaseUser.email, ...profile });
  });
}

export function logout() {
  return signOut(auth);
}

export async function changeCurrentPassword(newPassword) {
  if (!auth.currentUser) throw new Error('Nenhum usuário autenticado.');
  await updatePassword(auth.currentUser, newPassword);
}

export async function createManagedUser(currentUser, formData) {
  if (!currentUser || currentUser.role !== 'Administrador') throw new Error('Somente o administrador pode criar usuários.');

  const username = sanitizeUsername(formData.username);
  const email = usernameToEmail(username);
  const permissions = formData.permissions?.length ? formData.permissions : ensurePermissionsByRole(formData.role);

  const existing = await getDocs(query(refs.users, where('username', '==', username)));
  if (!existing.empty) throw new Error('Usuário já existe.');

  const tempAppName = `secondary-${crypto.randomUUID()}`;
  const secondaryApp = initializeApp(firebaseConfig, tempAppName);
  const secondaryAuth = getAuth(secondaryApp);

  const credential = await createUserWithEmailAndPassword(secondaryAuth, email, formData.password);
  await createDocWithId('users', credential.user.uid, {
    fullName: formData.fullName,
    username,
    email,
    role: formData.role,
    permissions,
    active: true,
    createdBy: currentUser.uid
  });

  await secondaryAuth.signOut();
  await secondaryApp.delete();
}

export async function updateManagedUser(currentUser, userId, formData) {
  if (!currentUser || currentUser.role !== 'Administrador') throw new Error('Somente o administrador pode editar usuários.');
  await updateByPath('users', userId, {
    fullName: formData.fullName,
    username: sanitizeUsername(formData.username),
    role: formData.role,
    permissions: formData.permissions?.length ? formData.permissions : ensurePermissionsByRole(formData.role),
    active: Boolean(formData.active)
  });
}

export async function deleteManagedUser(currentUser, userId) {
  if (!currentUser || currentUser.role !== 'Administrador') throw new Error('Somente o administrador pode excluir usuários.');
  await updateByPath('users', userId, { deleted: true, active: false });
}

export async function listUsers() {
  const users = await listCollection('users');
  return users.filter((user) => !user.deleted).sort((a, b) => (a.fullName || '').localeCompare(b.fullName || ''));
}
