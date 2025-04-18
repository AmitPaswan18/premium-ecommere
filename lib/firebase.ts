import { initializeApp } from "firebase/app"
import { getAuth } from "firebase/auth"

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyCNsmeM2Uu_Uu3N1cOoFmCXPSfuSh_n3D4",
  authDomain:"nextdashboard-57ae2.firebaseapp.com",
  projectId: "nextdashboard-57ae2",
  storageBucket:"nextdashboard-57ae2.firebasestorage.app",
  messagingSenderId:"749933222077",
  appId: "1:749933222077:web:5a64872efd493f72097fd4",
}


// Initialize Firebase
const app = initializeApp(firebaseConfig)

// Initialize Firebase Authentication and get a reference to the service
export const auth = getAuth(app)
export default app
