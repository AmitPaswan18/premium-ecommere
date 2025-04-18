"use client"

import { useCart } from "@/context/cart-context"
import { Separator } from "@/components/ui/separator"
import Image from "next/image"
import Link from "next/link"

export default function CheckoutSummary() {
  const { cart } = useCart()

  const subtotal = cart.items.reduce((total, item) => total + item.price * item.quantity, 0)
  const shipping = subtotal > 0 ? 10 : 0
  const total = subtotal + shipping

  return (
    <div className="bg-card rounded-lg shadow-sm p-6 sticky top-24">
      <h2 className="text-xl font-semibold mb-4">Order Summary</h2>

      <div className="space-y-4 mb-6">
        {cart.items.map((item) => (
          <div key={item.id} className="flex gap-3">
            <div className="relative h-16 w-16 rounded-md overflow-hidden bg-white flex-shrink-0">
              <Image src={item.image || "/placeholder.svg"} alt={item.title} fill className="object-contain p-2" />
            </div>
            <div className="flex-1 min-w-0">
              <Link href={`/products/${item.id}`} className="hover:underline">
                <h3 className="text-sm font-medium line-clamp-1">{item.title}</h3>
              </Link>
              <p className="text-sm text-muted-foreground">
                ${item.price.toFixed(2)} × {item.quantity}
              </p>
            </div>
            <p className="text-sm font-medium">${(item.price * item.quantity).toFixed(2)}</p>
          </div>
        ))}
      </div>

      <Separator className="my-4" />

      <div className="space-y-3">
        <div className="flex justify-between text-sm">
          <span>Subtotal</span>
          <span>${subtotal.toFixed(2)}</span>
        </div>
        <div className="flex justify-between text-sm">
          <span>Shipping</span>
          <span>${shipping.toFixed(2)}</span>
        </div>
        <Separator />
        <div className="flex justify-between font-semibold">
          <span>Total</span>
          <span>${total.toFixed(2)}</span>
        </div>
      </div>
    </div>
  )
}
