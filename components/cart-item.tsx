"use client"

import { useState } from "react"
import Image from "next/image"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { useCart } from "@/context/cart-context"
import { Minus, Plus, Trash } from "lucide-react"
import { motion } from "framer-motion"

export default function CartItem({ item }) {
  const { updateCartItemQuantity, removeFromCart } = useCart()
  const [isDragging, setIsDragging] = useState(false)

  const handleQuantityChange = (amount) => {
    const newQuantity = item.quantity + amount
    if (newQuantity >= 1) {
      updateCartItemQuantity(item.id, newQuantity)
    }
  }

  const handleRemove = () => {
    removeFromCart(item.id)
  }

  const handleDragStart = (e) => {
    e.dataTransfer.setData("text/plain", item.id)
    setIsDragging(true)
  }

  const handleDragEnd = () => {
    setIsDragging(false)
  }

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      transition={{ duration: 0.2 }}
      className={`${isDragging ? "opacity-50" : ""}`}
      draggable
      onDragStart={handleDragStart}
      onDragEnd={handleDragEnd}
    >
      <div className="flex gap-4">
        <div className="relative h-24 w-24 rounded-md overflow-hidden bg-white">
          <Image src={item.image || "/placeholder.svg"} alt={item.title} fill className="object-contain p-2" />
        </div>

        <div className="flex-1 min-w-0">
          <Link href={`/products/${item.id}`} className="hover:underline">
            <h3 className="font-medium line-clamp-1">{item.title}</h3>
          </Link>

          <div className="mt-1 flex items-center">
            <p className="text-sm text-muted-foreground">
              ${item.price.toFixed(2)} × {item.quantity}
            </p>
            <p className="ml-auto font-medium">${(item.price * item.quantity).toFixed(2)}</p>
          </div>

          <div className="mt-2 flex items-center gap-2">
            <div className="flex items-center border rounded-md">
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={() => handleQuantityChange(-1)}
                disabled={item.quantity <= 1}
              >
                <Minus className="h-3 w-3" />
                <span className="sr-only">Decrease quantity</span>
              </Button>
              <span className="w-8 text-center text-sm">{item.quantity}</span>
              <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => handleQuantityChange(1)}>
                <Plus className="h-3 w-3" />
                <span className="sr-only">Increase quantity</span>
              </Button>
            </div>

            <Button variant="ghost" size="icon" className="h-8 w-8 ml-auto" onClick={handleRemove}>
              <Trash className="h-4 w-4" />
              <span className="sr-only">Remove</span>
            </Button>
          </div>
        </div>
      </div>
      <Separator className="mt-4" />
    </motion.div>
  )
}
