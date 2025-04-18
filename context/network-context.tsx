"use client"

import { createContext, useContext, useEffect, useState } from "react"

const NetworkContext = createContext({
  isOnline: true,
})

export const useNetwork = () => useContext(NetworkContext)

export const NetworkStatusProvider = ({ children }) => {
  const [isOnline, setIsOnline] = useState(true)

  useEffect(() => {
    // Set initial state
    setIsOnline(navigator.onLine)

    // Add event listeners for online/offline events
    const handleOnline = () => setIsOnline(true)
    const handleOffline = () => setIsOnline(false)

    window.addEventListener("online", handleOnline)
    window.addEventListener("offline", handleOffline)

    return () => {
      window.removeEventListener("online", handleOnline)
      window.removeEventListener("offline", handleOffline)
    }
  }, [])

  return <NetworkContext.Provider value={{ isOnline }}>{children}</NetworkContext.Provider>
}
