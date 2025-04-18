import { getProducts } from "@/lib/api"
import ProductCard from "@/components/product-card"

export default async function FeaturedProducts() {
  const products = await getProducts()

  // For demo purposes, we'll just take the first 4 products
  const featuredProducts = products.slice(0, 4)

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
      {featuredProducts.map((product) => (
        <ProductCard key={product.id} product={product} />
      ))}
    </div>
  )
}
