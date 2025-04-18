"use client"

import { createContext, useContext, useEffect, useState } from "react"
import { useAuth } from "@/context/auth-context"
import { useNetwork } from "@/context/network-context"

const CartContext = createContext({
  cart: { items: [] },
  isLoading: true,
  addToCart: () => {},
  updateCartItemQuantity: () => {},
  removeFromCart: () => {},
  clearCart: () => {},
})

export const useCart = () => useContext(CartContext)

export const CartProvider = ({ children }) => {
  const [cart, setCart] = useState({ items: [] })
  const [isLoading, setIsLoading] = useState(true)
  const { user } = useAuth()
  const { isOnline } = useNetwork()

  // Load cart from localStorage on initial load
  useEffect(() => {
    const loadCart = () => {
      try {
        const savedCart = localStorage.getItem("cart")
        if (savedCart) {
          setCart(JSON.parse(savedCart))
        }
      } catch (error) {
        console.error("Error loading cart from localStorage:", error)
      } finally {
        setIsLoading(false)
      }
    }

    loadCart()
  }, [])

  // Load user-specific cart if user is logged in
  useEffect(() => {
    const loadUserCart = async () => {
      if (!user) return

      try {
        setIsLoading(true)

        // Try to get user-specific cart from localStorage first
        const userCartKey = `cart_${user.uid}`
        const savedUserCart = localStorage.getItem(userCartKey)

        if (savedUserCart) {
          const parsedCart = JSON.parse(savedUserCart)
          setCart(parsedCart)
        }

        // If online, we could also sync with a server here
        if (isOnline) {
          // For demo purposes, we're just using localStorage
          // In a real app, you would fetch from your API
        }
      } catch (error) {
        console.error("Error loading user cart:", error)
      } finally {
        setIsLoading(false)
      }
    }

    loadUserCart()
  }, [user, isOnline])

  // Save cart to localStorage whenever it changes
  useEffect(() => {
    if (isLoading) return

    try {
      // Save to general cart
      localStorage.setItem("cart", JSON.stringify(cart))

      // If user is logged in, also save to user-specific cart
      if (user) {
        const userCartKey = `cart_${user.uid}`
        localStorage.setItem(userCartKey, JSON.stringify(cart))
      }

      // If online, we could also sync with a server here
      if (isOnline && user) {
        // For demo purposes, we're just using localStorage
        // In a real app, you would send to your API
      }
    } catch (error) {
      console.error("Error saving cart to localStorage:", error)
    }
  }, [cart, user, isLoading, isOnline])

  const addToCart = (product) => {
    setCart((prevCart) => {
      const existingItemIndex = prevCart.items.findIndex((item) => item.id === product.id)

      if (existingItemIndex !== -1) {
        // Item already exists, update quantity
        const updatedItems = [...prevCart.items]
        updatedItems[existingItemIndex] = {
          ...updatedItems[existingItemIndex],
          quantity: updatedItems[existingItemIndex].quantity + product.quantity,
        }

        return { ...prevCart, items: updatedItems }
      } else {
        // Item doesn't exist, add it
        return {
          ...prevCart,
          items: [...prevCart.items, product],
        }
      }
    })
  }

  const updateCartItemQuantity = (productId, quantity) => {
    setCart((prevCart) => {
      const updatedItems = prevCart.items.map((item) => (item.id === productId ? { ...item, quantity } : item))

      return { ...prevCart, items: updatedItems }
    })
  }

  const removeFromCart = (productId) => {
    setCart((prevCart) => {
      const updatedItems = prevCart.items.filter((item) => item.id !== productId)

      return { ...prevCart, items: updatedItems }
    })
  }

  const clearCart = () => {
    setCart({ items: [] })
  }

  return (
    <CartContext.Provider
      value={{
        cart,
        isLoading,
        addToCart,
        updateCartItemQuantity,
        removeFromCart,
        clearCart,
      }}
    >
      {children}
    </CartContext.Provider>
  )
}
