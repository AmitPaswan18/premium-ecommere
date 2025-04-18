import { Suspense } from "react"
import ProductList from "@/components/product-list"
import ProductFilters from "@/components/product-filters"
import { ProductSkeleton } from "@/components/skeletons"

export const metadata = {
  title: "Products | Premium Shopping Experience",
  description: "Browse our collection of premium products",
}

export default function ProductsPage({
  searchParams,
}: {
  searchParams: { [key: string]: string | string[] | undefined }
}) {
  const category = searchParams.category as string | undefined
  const sort = searchParams.sort as string | undefined
  const minPrice = searchParams.minPrice as string | undefined
  const maxPrice = searchParams.maxPrice as string | undefined

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-8">Products</h1>
      <div className="flex flex-col md:flex-row gap-8">
        <div className="w-full md:w-1/4">
          <ProductFilters
            selectedCategory={category}
            selectedSort={sort}
            selectedPriceRange={{
              min: minPrice ? Number(minPrice) : undefined,
              max: maxPrice ? Number(maxPrice) : undefined,
            }}
          />
        </div>
        <div className="w-full md:w-3/4">
          <Suspense fallback={<ProductSkeleton count={8} />}>
            <ProductList
              category={category}
              sort={sort}
              priceRange={{
                min: minPrice ? Number(minPrice) : undefined,
                max: maxPrice ? Number(maxPrice) : undefined,
              }}
            />
          </Suspense>
        </div>
      </div>
    </div>
  )
}
