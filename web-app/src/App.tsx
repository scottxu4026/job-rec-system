import './App.css'
import { AppRouter } from './router'
import { AuthProvider } from './context/AuthContext'
import { ToastProvider } from './components/common/Toast'

function App() {
  return (
    <ToastProvider>
      <AuthProvider>
        <AppRouter />
      </AuthProvider>
    </ToastProvider>
  )
}

export default App
