import { initializeApp, getApps, getApp } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js';
import { getAuth } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js';
import { getFirestore } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-firestore.js';

export const firebaseConfig = {
  apiKey: "AIzaSyBfwjjEwhCEe07gSpT-8QGKECBztT7AoUo",
  authDomain: "gestao-69a63.firebaseapp.com",
  projectId: "gestao-69a63",
  storageBucket: "gestao-69a63.firebasestorage.app",
  messagingSenderId: "821882808210",
  appId: "1:821882808210:web:5ff38170aa333a3a8e834b"
};

export const app = getApps().length ? getApp() : initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);