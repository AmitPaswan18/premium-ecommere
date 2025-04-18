"use client"

import { useState } from "react"
import Image from "next/image"
import { Button } from "@/components/ui/button"
import { useToast } from "@/components/ui/use-toast"
import { useCart } from "@/context/cart-context"
import { useWishlist } from "@/context/wishlist-context"
import { Heart, Minus, Plus, ShoppingCart, Star } from "lucide-react"
import { motion, AnimatePresence } from "framer-motion"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"

export default function ProductDetails({ product }) {
  const [quantity, setQuantity] = useState(1)
  const [activeImage, setActiveImage] = useState(0)
  const [isImageZoomed, setIsImageZoomed] = useState(false)
  const { addToCart } = useCart()
  const { addToWishlist, removeFromWishlist, isInWishlist } = useWishlist()
  const { toast } = useToast()

  const isWishlisted = isInWishlist(product.id)

  // For demo purposes, we'll create some mock images
  const productImages = [
    product.image,
    "/placeholder.svg?height=400&width=400",
    "/placeholder.svg?height=400&width=400",
  ]

  const handleQuantityChange = (amount) => {
    const newQuantity = quantity + amount
    if (newQuantity >= 1) {
      setQuantity(newQuantity)
    }
  }

  const handleAddToCart = () => {
    addToCart({
      id: product.id,
      title: product.title,
      price: product.price,
      image: product.image,
      quantity,
    })

    toast({
      title: "Added to cart",
      description: `${product.title} has been added to your cart`,
    })
  }

  const handleToggleWishlist = () => {
    if (isWishlisted) {
      removeFromWishlist(product.id)
      toast({
        title: "Removed from wishlist",
        description: `${product.title} has been removed from your wishlist`,
      })
    } else {
      addToWishlist(product)
      toast({
        title: "Added to wishlist",
        description: `${product.title} has been added to your wishlist`,
      })
    }
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-8 lg:gap-12">
      <div className="space-y-4">
        <div className="relative aspect-square bg-white rounded-lg overflow-hidden">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeImage}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}
              className="relative h-full w-full"
              onClick={() => setIsImageZoomed(!isImageZoomed)}
            >
              <Image
                src={productImages[activeImage] || "/placeholder.svg"}
                alt={product.title}
                fill
                className={`object-contain p-4 cursor-zoom-in transition-transform duration-300 ${
                  isImageZoomed ? "scale-150" : "scale-100"
                }`}
              />
            </motion.div>
          </AnimatePresence>
        </div>

        <div className="flex space-x-2">
          {productImages.map((image, index) => (
            <button
              key={index}
              className={`relative w-16 h-16 rounded-md overflow-hidden border-2 ${
                activeImage === index ? "border-primary" : "border-transparent"
              }`}
              onClick={() => setActiveImage(index)}
            >
              <Image
                src={image || "/placeholder.svg"}
                alt={`Product thumbnail ${index + 1}`}
                fill
                className="object-contain p-1"
              />
            </button>
          ))}
        </div>
      </div>

      <div>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
        >
          <h1 className="text-2xl md:text-3xl font-bold">{product.title}</h1>

          <div className="flex items-center mt-2 space-x-2">
            <div className="flex">
              {[...Array(5)].map((_, i) => (
                <Star
                  key={i}
                  className={`h-4 w-4 ${
                    i < Math.round(product.rating.rate)
                      ? "fill-yellow-400 text-yellow-400"
                      : "fill-muted text-muted-foreground"
                  }`}
                />
              ))}
            </div>
            <span className="text-sm text-muted-foreground">
              {product.rating.rate} ({product.rating.count} reviews)
            </span>
          </div>

          <p className="text-2xl font-bold mt-4">${product.price.toFixed(2)}</p>

          <div className="mt-6 space-y-6">
            <div className="flex items-center space-x-4">
              <div className="flex items-center border rounded-md">
                <Button variant="ghost" size="icon" onClick={() => handleQuantityChange(-1)} disabled={quantity <= 1}>
                  <Minus className="h-4 w-4" />
                  <span className="sr-only">Decrease quantity</span>
                </Button>
                <span className="w-8 text-center">{quantity}</span>
                <Button variant="ghost" size="icon" onClick={() => handleQuantityChange(1)}>
                  <Plus className="h-4 w-4" />
                  <span className="sr-only">Increase quantity</span>
                </Button>
              </div>

              <Button className="flex-1" onClick={handleAddToCart}>
                <ShoppingCart className="h-4 w-4 mr-2" />
                Add to Cart
              </Button>

              <Button variant={isWishlisted ? "destructive" : "outline"} size="icon" onClick={handleToggleWishlist}>
                <Heart className={`h-4 w-4 ${isWishlisted ? "fill-current" : ""}`} />
                <span className="sr-only">{isWishlisted ? "Remove from wishlist" : "Add to wishlist"}</span>
              </Button>
            </div>

            <Tabs defaultValue="description">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="description">Description</TabsTrigger>
                <TabsTrigger value="details">Details</TabsTrigger>
                <TabsTrigger value="shipping">Shipping</TabsTrigger>
              </TabsList>
              <TabsContent value="description" className="pt-4">
                <p className="text-muted-foreground">{product.description}</p>
              </TabsContent>
              <TabsContent value="details" className="pt-4">
                <div className="space-y-2">
                  <div className="grid grid-cols-2 gap-2">
                    <span className="text-sm font-medium">Category</span>
                    <span className="text-sm text-muted-foreground capitalize">{product.category}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <span className="text-sm font-medium">Material</span>
                    <span className="text-sm text-muted-foreground">Premium Quality</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <span className="text-sm font-medium">Brand</span>
                    <span className="text-sm text-muted-foreground">LuxeShop</span>
                  </div>
                </div>
              </TabsContent>
              <TabsContent value="shipping" className="pt-4">
                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground">
                    Free shipping on orders over $50. Standard delivery 3-5 business days.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    Express delivery available (2-3 business days) for an additional fee.
                  </p>
                  <p className="text-sm text-muted-foreground">
                    30-day return policy for unused items in original packaging.
                  </p>
                </div>
              </TabsContent>
            </Tabs>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
