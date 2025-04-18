"use client"

import { useWishlist } from "@/context/wishlist-context"
import { useCart } from "@/context/cart-context"
import { Button } from "@/components/ui/button"
import { useToast } from "@/components/ui/use-toast"
import { Heart, Loader2, ShoppingCart } from "lucide-react"
import Image from "next/image"
import Link from "next/link"
import { motion } from "framer-motion"

export default function WishlistTab() {
  const { wishlist, removeFromWishlist, isLoading } = useWishlist()
  const { addToCart } = useCart()
  const { toast } = useToast()

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

  const handleRemoveFromWishlist = (productId, productTitle) => {
    removeFromWishlist(productId)

    toast({
      title: "Removed from wishlist",
      description: `${productTitle} has been removed from your wishlist`,
    })
  }

  if (isLoading) {
    return (
      <div className="flex justify-center items-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    )
  }

  if (wishlist.length === 0) {
    return (
      <div className="text-center py-12">
        <Heart className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
        <h2 className="text-xl font-semibold mb-2">Your wishlist is empty</h2>
        <p className="text-muted-foreground mb-6">Save items you love to your wishlist and they'll appear here.</p>
        <Button asChild>
          <a href="/products">Start Shopping</a>
        </Button>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      {wishlist.map((product, index) => (
        <motion.div
          key={product.id}
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.3, delay: index * 0.05 }}
          className="bg-card rounded-lg shadow-sm overflow-hidden group"
        >
          <div className="relative aspect-square bg-white">
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
              onClick={() => handleRemoveFromWishlist(product.id, product.title)}
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
  )
}
