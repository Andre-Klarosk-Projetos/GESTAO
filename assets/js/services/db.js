import {
  addDoc,
  collection,
  doc,
  getDocs,
  onSnapshot,
  orderBy as firestoreOrderBy,
  query,
  serverTimestamp,
  Timestamp,
  updateDoc
} from "https://www.gstatic.com/firebasejs/10.12.5/firebase-firestore.js";

import { db } from "../firebase-config.js";

export const refs = {
  users: collection(db, "users"),
  products: collection(db, "products"),
  sales: collection(db, "sales"),
  deliveries: collection(db, "deliveries"),
  settings: collection(db, "settings")
};

export function orderBy(field, direction = "asc") {
  return firestoreOrderBy(field, direction);
}

export async function createDoc(collectionRef, payload = {}) {
  const data = {
    ...payload,
    createdAt: payload.createdAt || serverTimestamp(),
    updatedAt: serverTimestamp()
  };

  const created = await addDoc(collectionRef, data);
  return created.id;
}

export async function updateByPath(collectionName, documentId, payload = {}) {
  const ref = doc(db, collectionName, documentId);

  await updateDoc(ref, {
    ...payload,
    updatedAt: serverTimestamp()
  });

  return true;
}

export async function listCollection(collectionName, queryConstraints = []) {
  const ref = collection(db, collectionName);
  const q = query(ref, ...queryConstraints);
  const snap = await getDocs(q);

  return snap.docs.map((item) => ({
    id: item.id,
    ...item.data()
  }));
}

export function subscribeCollection(collectionName, queryConstraints = [], callback) {
  const ref = collection(db, collectionName);
  const q = query(ref, ...queryConstraints);

  return onSnapshot(q, (snap) => {
    const rows = snap.docs.map((item) => ({
      id: item.id,
      ...item.data()
    }));

    callback(rows);
  });
}

export function timestampFromDateTime(dateValue, timeValue) {
  if (!dateValue) {
    return Timestamp.now();
  }

  const safeTime = timeValue || "00:00";
  const iso = `${dateValue}T${safeTime}:00`;
  const date = new Date(iso);

  return Timestamp.fromDate(date);
}