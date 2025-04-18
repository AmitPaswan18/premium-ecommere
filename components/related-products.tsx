import { getProducts } from "@/lib/api"
import ProductCard from "@/components/product-card"

export default async function RelatedProducts({ category, currentProductId, limit = 4 }) {
  const products = await getProducts()

  // Filter products by category and exclude current product
  const relatedProducts = products
    .filter((product) => product.category === category && product.id.toString() !== currentProductId.toString())
    .slice(0, limit)

  if (relatedProducts.length === 0) {
    return null
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
      {relatedProducts.map((product) => (
        <ProductCard key={product.id} product={product} />
      ))}
    </div>
  )
}
