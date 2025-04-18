import { Suspense } from "react"
import { notFound } from "next/navigation"
import ProductDetails from "@/components/product-details"
import RelatedProducts from "@/components/related-products"
import { ProductDetailsSkeleton, ProductSkeleton } from "@/components/skeletons"
import { getProductById } from "@/lib/api"

export async function generateMetadata({ params }: { params: { id: string } }) {
  const product = await getProductById(params.id)

  if (!product) {
    return {
      title: "Product Not Found",
      description: "The requested product could not be found",
    }
  }

  return {
    title: `${product.title} | Premium Shopping Experience`,
    description: product.description,
  }
}

export default async function ProductPage({ params }: { params: { id: string } }) {
  const product = await getProductById(params.id)

  if (!product) {
    notFound()
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <Suspense fallback={<ProductDetailsSkeleton />}>
        <ProductDetails product={product} />
      </Suspense>
      <div className="mt-16">
        <h2 className="text-2xl font-bold mb-8">You might also like</h2>
        <Suspense fallback={<ProductSkeleton count={4} />}>
          <RelatedProducts category={product.category} currentProductId={product.id} />
        </Suspense>
      </div>
    </div>
  )
}
