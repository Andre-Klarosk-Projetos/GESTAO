import { initializeApp, getApps, getApp } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js';
import { getAuth } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js';
import { getFirestore } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-firestore.js';

export const firebaseConfig = {
  apiKey: 'AIzaSyCHco_BVJDnqNFokxklmWsK4VAkbAKsMZo',
  authDomain: 'gestao-975a2.firebaseapp.com',
  projectId: 'gestao-975a2',
  storageBucket: 'gestao-975a2.firebasestorage.app',
  messagingSenderId: '150777984533',
  appId: '1:150777984533:web:80807b25bedf420f0e801c',
  measurementId: 'G-H0MK7WX75F'
};

export const app = getApps().length ? getApp() : initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
