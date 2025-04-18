import { getProducts } from "@/lib/api"
import ProductCard from "@/components/product-card"

export default async function ProductList({
  category,
  sort,
  priceRange,
  limit = 100,
}: {
  category?: string
  sort?: string
  priceRange?: { min?: number; max?: number }
  limit?: number
}) {
  const products = await getProducts()

  let filteredProducts = [...products]

  // Filter by category if provided
  if (category) {
    filteredProducts = filteredProducts.filter((product) => product.category.toLowerCase() === category.toLowerCase())
  }

  // Filter by price range if provided
  if (priceRange) {
    if (priceRange.min !== undefined) {
      filteredProducts = filteredProducts.filter((product) => product.price >= priceRange.min)
    }
    if (priceRange.max !== undefined) {
      filteredProducts = filteredProducts.filter((product) => product.price <= priceRange.max)
    }
  }

  // Sort products
  if (sort) {
    switch (sort) {
      case "price-low-high":
        filteredProducts.sort((a, b) => a.price - b.price)
        break
      case "price-high-low":
        filteredProducts.sort((a, b) => b.price - a.price)
        break
      case "rating":
        filteredProducts.sort((a, b) => b.rating.rate - a.rating.rate)
        break
      case "newest":
        // For demo purposes, we'll just reverse the array
        filteredProducts.reverse()
        break
      default:
        // Default sorting (by id)
        break
    }
  }

  // Limit the number of products
  filteredProducts = filteredProducts.slice(0, limit)

  if (filteredProducts.length === 0) {
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold mb-2">No products found</h2>
        <p className="text-muted-foreground">Try adjusting your filters to find what you're looking for.</p>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
      {filteredProducts.map((product) => (
        <ProductCard key={product.id} product={product} />
      ))}
    </div>
  )
}
