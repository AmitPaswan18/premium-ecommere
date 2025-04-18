"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/context/auth-context"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useToast } from "@/components/ui/use-toast"
import { motion } from "framer-motion"
import OrderHistory from "@/components/profile/order-history"
import WishlistTab from "@/components/profile/wishlist-tab"
import ProfileSettings from "@/components/profile/profile-settings"
import { Loader2 } from "lucide-react"

export default function ProfilePage() {
  const { user, isLoading: authLoading } = useAuth()
  const [orders, setOrders] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const router = useRouter()
  const { toast } = useToast()

  useEffect(() => {
    if (!authLoading && !user) {
      router.push("/auth/signin?redirect=/profile")
    }
  }, [user, authLoading, router])

  useEffect(() => {
    const fetchOrders = async () => {
      if (!user) return

      try {
        setIsLoading(true)
        // In a real app, we would fetch from a real API
        // For demo purposes, we'll create some mock orders
        const mockOrders = [
          {
            id: "ORD-1234-5678",
            date: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
            status: "delivered",
            total: 129.99,
            items: [
              { id: 1, title: "Fjallraven Backpack", price: 109.99, quantity: 1 },
              { id: 2, title: "Mens Cotton Jacket", price: 20.0, quantity: 1 },
            ],
          },
          {
            id: "ORD-8765-4321",
            date: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
            status: "delivered",
            total: 55.99,
            items: [{ id: 3, title: "Mens Casual Slim Fit", price: 55.99, quantity: 1 }],
          },
        ]

        setOrders(mockOrders)
      } catch (error) {
        console.error("Error fetching orders:", error)
        toast({
          title: "Error fetching orders",
          description: "There was a problem loading your order history",
          variant: "destructive",
        })
      } finally {
        setIsLoading(false)
      }
    }

    fetchOrders()
  }, [user, toast])

  if (authLoading) {
    return (
      <div className="container mx-auto px-4 py-16 flex justify-center items-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  if (!user) {
    return null // Will redirect in the useEffect
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-8">My Account</h1>

      <Tabs defaultValue="orders" className="w-full">
        <TabsList className="grid w-full grid-cols-3 mb-8">
          <TabsTrigger value="orders">Order History</TabsTrigger>
          <TabsTrigger value="wishlist">Wishlist</TabsTrigger>
          <TabsTrigger value="settings">Account Settings</TabsTrigger>
        </TabsList>

        <TabsContent value="orders">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <OrderHistory orders={orders} isLoading={isLoading} />
          </motion.div>
        </TabsContent>

        <TabsContent value="wishlist">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <WishlistTab />
          </motion.div>
        </TabsContent>

        <TabsContent value="settings">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <ProfileSettings user={user} />
          </motion.div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
