"use client"

import { motion } from "framer-motion"
import Link from "next/link"

const categories = [
  {
    id: "men's clothing",
    name: "Men's Clothing",
    image: "/placeholder.svg?height=200&width=200",
  },
  {
    id: "women's clothing",
    name: "Women's Clothing",
    image: "/placeholder.svg?height=200&width=200",
  },
  {
    id: "jewelery",
    name: "Jewelry",
    image: "/placeholder.svg?height=200&width=200",
  },
  {
    id: "electronics",
    name: "Electronics",
    image: "/placeholder.svg?height=200&width=200",
  },
]

export default function Categories() {
  return (
    <section className="py-12">
      <h2 className="text-3xl font-bold mb-8 text-center">Shop by Category</h2>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {categories.map((category, index) => (
          <motion.div
            key={category.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: index * 0.1 }}
          >
            <Link
              href={`/products?category=${category.id}`}
              className="block group relative overflow-hidden rounded-lg"
            >
              <div className="aspect-square bg-muted relative">
                <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent z-10" />
                <img
                  src={category.image || "/placeholder.svg"}
                  alt={category.name}
                  className="w-full h-full object-cover transition-transform duration-300 group-hover:scale-105"
                />
                <div className="absolute bottom-0 left-0 right-0 p-4 z-20">
                  <h3 className="text-xl font-semibold text-white">{category.name}</h3>
                </div>
              </div>
            </Link>
          </motion.div>
        ))}
      </div>
    </section>
  )
}
