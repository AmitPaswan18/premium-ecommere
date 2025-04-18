"use client"

import { createContext, useContext, useEffect, useState } from "react"
import { useAuth } from "@/context/auth-context"
import { useNetwork } from "@/context/network-context"

const WishlistContext = createContext({
  wishlist: [],
  isLoading: true,
  addToWishlist: () => {},
  removeFromWishlist: () => {},
  isInWishlist: () => false,
})

export const useWishlist = () => useContext(WishlistContext)

export const WishlistProvider = ({ children }) => {
  const [wishlist, setWishlist] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const { user } = useAuth()
  const { isOnline } = useNetwork()

  // Load wishlist from localStorage on initial load
  useEffect(() => {
    const loadWishlist = () => {
      try {
        // If user is logged in, try to get user-specific wishlist
        if (user) {
          const userWishlistKey = `wishlist_${user.uid}`
          const savedUserWishlist = localStorage.getItem(userWishlistKey)

          if (savedUserWishlist) {
            setWishlist(JSON.parse(savedUserWishlist))
            setIsLoading(false)
            return
          }
        }

        // Fallback to general wishlist
        const savedWishlist = localStorage.getItem("wishlist")
        if (savedWishlist) {
          setWishlist(JSON.parse(savedWishlist))
        }
      } catch (error) {
        console.error("Error loading wishlist from localStorage:", error)
      } finally {
        setIsLoading(false)
      }
    }

    loadWishlist()
  }, [user])

  // Save wishlist to localStorage whenever it changes
  useEffect(() => {
    if (isLoading) return

    try {
      // Save to general wishlist
      localStorage.setItem("wishlist", JSON.stringify(wishlist))

      // If user is logged in, also save to user-specific wishlist
      if (user) {
        const userWishlistKey = `wishlist_${user.uid}`
        localStorage.setItem(userWishlistKey, JSON.stringify(wishlist))
      }

      // If online, we could also sync with a server here
      if (isOnline && user) {
        // For demo purposes, we're just using localStorage
        // In a real app, you would send to your API
      }
    } catch (error) {
      console.error("Error saving wishlist to localStorage:", error)
    }
  }, [wishlist, user, isLoading, isOnline])

  const addToWishlist = (product) => {
    setWishlist((prevWishlist) => {
      // Check if product already exists in wishlist
      if (prevWishlist.some((item) => item.id === product.id)) {
        return prevWishlist
      }

      return [...prevWishlist, product]
    })
  }

  const removeFromWishlist = (productId) => {
    setWishlist((prevWishlist) => prevWishlist.filter((item) => item.id !== productId))
  }

  const isInWishlist = (productId) => {
    return wishlist.some((item) => item.id === productId)
  }

  return (
    <WishlistContext.Provider
      value={{
        wishlist,
        isLoading,
        addToWishlist,
        removeFromWishlist,
        isInWishlist,
      }}
    >
      {children}
    </WishlistContext.Provider>
  )
}
