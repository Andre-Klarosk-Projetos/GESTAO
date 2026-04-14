import {
  collection,
  addDoc,
  doc,
  setDoc,
  updateDoc,
  getDoc,
  getDocs,
  query,
  where,
  orderBy,
  onSnapshot,
  serverTimestamp,
  Timestamp
} from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-firestore.js';
import { db } from '../firebase-config.js';

export const refs = {
  users: collection(db, 'users'),
  products: collection(db, 'products'),
  sales: collection(db, 'sales'),
  deliveries: collection(db, 'deliveries'),
  settings: collection(db, 'settings')
};

export const serverNow = () => serverTimestamp();
export const timestampFromDateTime = (date, time = '00:00') => Timestamp.fromDate(new Date(`${date}T${time}:00`));

export async function createDoc(collectionRef, data) {
  return addDoc(collectionRef, { ...data, createdAt: serverTimestamp(), updatedAt: serverTimestamp() });
}

export async function createDocWithId(path, id, data) {
  return setDoc(doc(db, path, id), { ...data, createdAt: serverTimestamp(), updatedAt: serverTimestamp() });
}

export async function updateByPath(path, id, data) {
  return updateDoc(doc(db, path, id), { ...data, updatedAt: serverTimestamp() });
}

export async function getByPath(path, id) {
  return getDoc(doc(db, path, id));
}

export async function listCollection(name, constraints = []) {
  const q = query(collection(db, name), ...constraints);
  const snapshot = await getDocs(q);
  return snapshot.docs.map((item) => ({ id: item.id, ...item.data() }));
}

export function subscribeCollection(name, constraints, callback) {
  const q = query(collection(db, name), ...constraints);
  return onSnapshot(q, (snapshot) => {
    callback(snapshot.docs.map((item) => ({ id: item.id, ...item.data() })));
  });
}

export { where, orderBy, getDocs, query, doc, setDoc, getDoc };
