"use client"

import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { motion } from "framer-motion"
import { Loader2 } from "lucide-react"

export default function ReviewOrder({ shippingDetails, paymentDetails, onBack, onPlaceOrder, isSubmitting }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-card rounded-lg shadow-sm p-6"
    >
      <h2 className="text-xl font-semibold mb-6">Review Your Order</h2>

      <div className="space-y-6">
        <div>
          <h3 className="font-medium mb-2">Shipping Information</h3>
          <div className="text-sm text-muted-foreground">
            <p>{shippingDetails.fullName}</p>
            <p>{shippingDetails.email}</p>
            <p>{shippingDetails.address}</p>
            <p>
              {shippingDetails.city}, {shippingDetails.state} {shippingDetails.zipCode}
            </p>
            <p>{shippingDetails.country}</p>
          </div>
        </div>

        <Separator />

        <div>
          <h3 className="font-medium mb-2">Payment Information</h3>
          <div className="text-sm text-muted-foreground">
            <p>Card: **** **** **** {paymentDetails.cardNumber.slice(-4)}</p>
            <p>Name: {paymentDetails.cardName}</p>
            <p>Expires: {paymentDetails.expiryDate}</p>
          </div>
        </div>

        <Separator />

        <div className="space-y-2">
          <p className="text-sm">By placing your order, you agree to our Terms of Service and Privacy Policy.</p>
          <p className="text-sm">Your payment information is encrypted and secure.</p>
        </div>

        <div className="flex gap-4 mt-6">
          <Button type="button" variant="outline" onClick={onBack} disabled={isSubmitting}>
            Back
          </Button>
          <Button className="flex-1" onClick={onPlaceOrder} disabled={isSubmitting}>
            {isSubmitting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Processing...
              </>
            ) : (
              "Place Order"
            )}
          </Button>
        </div>
      </div>
    </motion.div>
  )
}
