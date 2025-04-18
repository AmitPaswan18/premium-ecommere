"use client"

import { Button } from "@/components/ui/button"
import { motion } from "framer-motion"
import { CheckCircle } from "lucide-react"
import Link from "next/link"
import confetti from "canvas-confetti"
import { useEffect } from "react"

export default function OrderConfirmation({ orderId }) {
  useEffect(() => {
    // Trigger confetti animation
    confetti({
      particleCount: 100,
      spread: 70,
      origin: { y: 0.6 },
    })
  }, [])

  return (
    <div className="container mx-auto px-4 py-16 text-center">
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5 }}
        className="max-w-md mx-auto"
      >
        <div className="flex justify-center mb-6">
          <CheckCircle className="h-16 w-16 text-green-500" />
        </div>

        <h1 className="text-3xl font-bold mb-4">Order Confirmed!</h1>

        <p className="text-muted-foreground mb-2">Thank you for your purchase. Your order has been confirmed.</p>

        <p className="text-lg font-medium mb-8">
          Order Number: <span className="text-primary">{orderId}</span>
        </p>

        <div className="bg-card rounded-lg shadow-sm p-6 mb-8">
          <h2 className="text-lg font-semibold mb-4">What's Next?</h2>
          <ol className="text-left space-y-2 text-muted-foreground">
            <li>1. You'll receive an email confirmation shortly.</li>
            <li>2. We'll process your order within 24 hours.</li>
            <li>3. Your items will be shipped and you'll receive tracking information.</li>
            <li>4. Enjoy your new products!</li>
          </ol>
        </div>

        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Button asChild>
            <Link href="/products">Continue Shopping</Link>
          </Button>
          <Button variant="outline" asChild>
            <Link href="/profile?tab=orders">View Order History</Link>
          </Button>
        </div>
      </motion.div>
    </div>
  )
}
