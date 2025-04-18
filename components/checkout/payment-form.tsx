"use client"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useForm } from "react-hook-form"
import { motion } from "framer-motion"
import { CreditCard } from "lucide-react"

export default function PaymentForm({ onSubmit, onBack, defaultValues = {} }) {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({
    defaultValues: {
      cardNumber: defaultValues.cardNumber || "",
      cardName: defaultValues.cardName || "",
      expiryDate: defaultValues.expiryDate || "",
      cvv: defaultValues.cvv || "",
    },
  })

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.3 }}
      className="bg-card rounded-lg shadow-sm p-6"
    >
      <h2 className="text-xl font-semibold mb-6">Payment Information</h2>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
        <div className="space-y-2">
          <Label htmlFor="cardNumber">Card Number</Label>
          <div className="relative">
            <CreditCard className="absolute left-3 top-2.5 h-5 w-5 text-muted-foreground" />
            <Input
              id="cardNumber"
              className="pl-10"
              {...register("cardNumber", {
                required: "Card number is required",
                pattern: {
                  value: /^[0-9]{16}$/,
                  message: "Please enter a valid 16-digit card number",
                },
              })}
              placeholder="1234 5678 9012 3456"
              maxLength={16}
            />
          </div>
          {errors.cardNumber && <p className="text-sm text-destructive">{errors.cardNumber.message}</p>}
        </div>

        <div className="space-y-2">
          <Label htmlFor="cardName">Name on Card</Label>
          <Input
            id="cardName"
            {...register("cardName", { required: "Name on card is required" })}
            placeholder="John Doe"
          />
          {errors.cardName && <p className="text-sm text-destructive">{errors.cardName.message}</p>}
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label htmlFor="expiryDate">Expiry Date</Label>
            <Input
              id="expiryDate"
              {...register("expiryDate", {
                required: "Expiry date is required",
                pattern: {
                  value: /^(0[1-9]|1[0-2])\/([0-9]{2})$/,
                  message: "Please use MM/YY format",
                },
              })}
              placeholder="MM/YY"
            />
            {errors.expiryDate && <p className="text-sm text-destructive">{errors.expiryDate.message}</p>}
          </div>

          <div className="space-y-2">
            <Label htmlFor="cvv">CVV</Label>
            <Input
              id="cvv"
              type="password"
              {...register("cvv", {
                required: "CVV is required",
                pattern: {
                  value: /^[0-9]{3,4}$/,
                  message: "Please enter a valid CVV",
                },
              })}
              placeholder="123"
              maxLength={4}
            />
            {errors.cvv && <p className="text-sm text-destructive">{errors.cvv.message}</p>}
          </div>
        </div>

        <div className="flex gap-4 mt-6">
          <Button type="button" variant="outline" onClick={onBack}>
            Back
          </Button>
          <Button type="submit" className="flex-1">
            Continue to Review
          </Button>
        </div>
      </form>
    </motion.div>
  )
}
