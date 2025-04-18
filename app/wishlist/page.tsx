"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/context/auth-context"
import { useWishlist } from "@/context/wishlist-context"
import { Button } from "@/components/ui/button"
import { useToast } from "@/components/ui/use-toast"
import { motion } from "framer-motion"
import { Heart, Loader2, ShoppingCart } from "lucide-react"
import Link from "next/link"
import Image from "next/image"
import { useCart } from "@/context/cart-context"

export default function WishlistPage() {
  const { user, isLoading: authLoading } = useAuth()
  const { wishlist, removeFromWishlist, isLoading: wishlistLoading } = useWishlist()
  const { addToCart } = useCart()
  const router = useRouter()
  const { toast } = useToast()

  useEffect(() => {
    if (!authLoading && !user) {
      router.push("/auth/signin?redirect=/wishlist")
    }
  }, [user, authLoading, router])

  const handleAddToCart = (product) => {
    addToCart({
      id: product.id,
      title: product.title,
      price: product.price,
      image: product.image,
      quantity: 1,
    })

    toast({
      title: "Added to cart",
      description: `${product.title} has been added to your cart`,
    })
  }

  const handleRemoveFromWishlist = (productId) => {
    removeFromWishlist(productId)

    toast({
      title: "Removed from wishlist",
      description: "The item has been removed from your wishlist",
    })
  }

  if (authLoading || wishlistLoading) {
    return (
      <div className="container mx-auto px-4 py-16 flex justify-center items-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  if (!user) {
    return null // Will redirect in the useEffect
  }

  if (wishlist.length === 0) {
    return (
      <div className="container mx-auto px-4 py-16 text-center">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="flex flex-col items-center gap-4"
        >
          <Heart className="h-16 w-16 text-muted-foreground" />
          <h1 className="text-2xl font-bold">Your wishlist is empty</h1>
          <p className="text-muted-foreground mb-4">Save items you love to your wishlist and they'll appear here.</p>
          <Button asChild>
            <Link href="/products">Start Shopping</Link>
          </Button>
        </motion.div>
      </div>
    )
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-8">My Wishlist</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {wishlist.map((product) => (
          <motion.div
            key={product.id}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.3 }}
            className="bg-card rounded-lg shadow-sm overflow-hidden group"
          >
            <div className="relative aspect-square">
              <Image
                src={product.image || "/placeholder.svg"}
                alt={product.title}
                fill
                className="object-contain p-4 group-hover:scale-105 transition-transform duration-300"
              />
              <Button
                variant="destructive"
                size="icon"
                className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity"
                onClick={() => handleRemoveFromWishlist(product.id)}
              >
                <Heart className="h-4 w-4 fill-current" />
                <span className="sr-only">Remove from wishlist</span>
              </Button>
            </div>

            <div className="p-4">
              <Link href={`/products/${product.id}`} className="hover:underline">
                <h2 className="font-semibold line-clamp-1">{product.title}</h2>
              </Link>
              <p className="text-lg font-bold mt-2">${product.price.toFixed(2)}</p>

              <Button className="w-full mt-4" onClick={() => handleAddToCart(product)}>
                <ShoppingCart className="h-4 w-4 mr-2" />
                Add to Cart
              </Button>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  )
}
