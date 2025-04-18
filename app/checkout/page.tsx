"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useCart } from "@/context/cart-context"
import { useAuth } from "@/context/auth-context"
import { useToast } from "@/components/ui/use-toast"
import { motion, AnimatePresence } from "framer-motion"
import CheckoutSummary from "@/components/checkout-summary"
import ShippingForm from "@/components/checkout/shipping-form"
import PaymentForm from "@/components/checkout/payment-form"
import ReviewOrder from "@/components/checkout/review-order"
import OrderConfirmation from "@/components/checkout/order-confirmation"
import { createOrder } from "@/lib/api"

const steps = ["Shipping", "Payment", "Review"]

export default function CheckoutPage() {
  const [currentStep, setCurrentStep] = useState(0)
  const [shippingDetails, setShippingDetails] = useState({
    fullName: "",
    email: "",
    address: "",
    city: "",
    state: "",
    zipCode: "",
    country: "United States",
  })
  const [paymentDetails, setPaymentDetails] = useState({
    cardNumber: "",
    cardName: "",
    expiryDate: "",
    cvv: "",
  })
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isComplete, setIsComplete] = useState(false)
  const [orderId, setOrderId] = useState("")

  const { cart, clearCart } = useCart()
  const { user } = useAuth()
  const router = useRouter()
  const { toast } = useToast()

  const handleShippingSubmit = (data) => {
    setShippingDetails(data)
    setCurrentStep(1)
    window.scrollTo(0, 0)
  }

  const handlePaymentSubmit = (data) => {
    setPaymentDetails(data)
    setCurrentStep(2)
    window.scrollTo(0, 0)
  }

  const handlePlaceOrder = async () => {
    if (!user) {
      toast({
        title: "Authentication required",
        description: "Please sign in to complete your order",
        variant: "destructive",
      })
      router.push("/auth/signin?redirect=/checkout")
      return
    }

    setIsSubmitting(true)

    try {
      // Create a new order
      const orderData = {
        userId: user.uid,
        products: cart.items.map((item) => ({
          productId: item.id,
          quantity: item.quantity,
        })),
        total: cart.items.reduce((total, item) => total + item.price * item.quantity, 0) + 10,
        shippingDetails,
        paymentDetails: {
          cardNumber: paymentDetails.cardNumber.slice(-4),
          cardName: paymentDetails.cardName,
        },
        status: "processing",
        date: new Date().toISOString(),
      }

      const response = await createOrder(orderData)

      // Generate a random order ID for demo purposes
      const generatedOrderId = `ORD-${Math.floor(Math.random() * 10000)}-${Date.now().toString().slice(-4)}`
      setOrderId(generatedOrderId)

      // Clear the cart
      clearCart()

      // Show success
      setIsComplete(true)

      // Scroll to top
      window.scrollTo(0, 0)
    } catch (error) {
      console.error("Error placing order:", error)
      toast({
        title: "Error placing order",
        description: "There was a problem processing your order. Please try again.",
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }

  const goBack = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1)
      window.scrollTo(0, 0)
    }
  }

  if (isComplete) {
    return <OrderConfirmation orderId={orderId} />
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-8">Checkout</h1>

      {!isComplete && (
        <div className="mb-8">
          <div className="flex justify-between">
            {steps.map((step, index) => (
              <div key={step} className="flex flex-col items-center">
                <div
                  className={`w-10 h-10 rounded-full flex items-center justify-center ${
                    index < currentStep
                      ? "bg-primary text-primary-foreground"
                      : index === currentStep
                        ? "bg-primary text-primary-foreground"
                        : "bg-muted text-muted-foreground"
                  }`}
                >
                  {index < currentStep ? "✓" : index + 1}
                </div>
                <span className="mt-2 text-sm">{step}</span>
              </div>
            ))}
          </div>
          <div className="relative mt-2">
            <div className="absolute top-0 left-0 right-0 h-1 bg-muted">
              <div
                className="h-full bg-primary transition-all duration-300"
                style={{ width: `${(currentStep / (steps.length - 1)) * 100}%` }}
              ></div>
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-col lg:flex-row gap-8">
        <div className="flex-1">
          <AnimatePresence mode="wait">
            {currentStep === 0 && (
              <motion.div
                key="shipping"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.3 }}
              >
                <ShippingForm onSubmit={handleShippingSubmit} defaultValues={shippingDetails} />
              </motion.div>
            )}

            {currentStep === 1 && (
              <motion.div
                key="payment"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.3 }}
              >
                <PaymentForm onSubmit={handlePaymentSubmit} defaultValues={paymentDetails} onBack={goBack} />
              </motion.div>
            )}

            {currentStep === 2 && (
              <motion.div
                key="review"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ duration: 0.3 }}
              >
                <ReviewOrder
                  shippingDetails={shippingDetails}
                  paymentDetails={paymentDetails}
                  onBack={goBack}
                  onPlaceOrder={handlePlaceOrder}
                  isSubmitting={isSubmitting}
                />
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <div className="w-full lg:w-1/3">
          <CheckoutSummary />
        </div>
      </div>
    </div>
  )
}
