"use client"

import { useState, useEffect } from "react"
import { useRouter, usePathname, useSearchParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Slider } from "@/components/ui/slider"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { motion, AnimatePresence } from "framer-motion"

const categories = [
  { id: "men's clothing", label: "Men's Clothing" },
  { id: "women's clothing", label: "Women's Clothing" },
  { id: "jewelery", label: "Jewelry" },
  { id: "electronics", label: "Electronics" },
]

const sortOptions = [
  { value: "featured", label: "Featured" },
  { value: "newest", label: "Newest" },
  { value: "price-low-high", label: "Price: Low to High" },
  { value: "price-high-low", label: "Price: High to Low" },
  { value: "rating", label: "Top Rated" },
]

export default function ProductFilters({
  selectedCategory,
  selectedSort = "featured",
  selectedPriceRange = { min: 0, max: 1000 },
}) {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()

  const [priceRange, setPriceRange] = useState([selectedPriceRange.min || 0, selectedPriceRange.max || 1000])
  const [isFilterVisible, setIsFilterVisible] = useState(false)

  useEffect(() => {
    setIsFilterVisible(true)
  }, [])

  const createQueryString = (params) => {
    const newSearchParams = new URLSearchParams(searchParams.toString())

    Object.entries(params).forEach(([name, value]) => {
      if (value === undefined || value === null) {
        newSearchParams.delete(name)
      } else {
        newSearchParams.set(name, value)
      }
    })

    return newSearchParams.toString()
  }

  const handleCategoryChange = (categoryId) => {
    router.push(
      `${pathname}?${createQueryString({
        category: categoryId === selectedCategory ? undefined : categoryId,
      })}`,
    )
  }

  const handleSortChange = (value) => {
    router.push(
      `${pathname}?${createQueryString({
        sort: value,
      })}`,
    )
  }

  const handlePriceChange = (values) => {
    setPriceRange(values)
  }

  const handlePriceApply = () => {
    router.push(
      `${pathname}?${createQueryString({
        minPrice: priceRange[0],
        maxPrice: priceRange[1],
      })}`,
    )
  }

  const handleClearFilters = () => {
    router.push(pathname)
  }

  const hasActiveFilters =
    selectedCategory ||
    selectedSort !== "featured" ||
    selectedPriceRange.min !== undefined ||
    selectedPriceRange.max !== undefined

  return (
    <AnimatePresence>
      {isFilterVisible && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="bg-card rounded-lg shadow-sm p-6"
        >
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-lg font-semibold">Filters</h2>
            {hasActiveFilters && (
              <Button variant="ghost" size="sm" onClick={handleClearFilters}>
                Clear All
              </Button>
            )}
          </div>

          <div className="space-y-6">
            <div>
              <h3 className="text-sm font-medium mb-3">Sort By</h3>
              <Select value={selectedSort} onValueChange={handleSortChange}>
                <SelectTrigger>
                  <SelectValue placeholder="Select" />
                </SelectTrigger>
                <SelectContent>
                  {sortOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <Accordion type="single" collapsible defaultValue="category">
              <AccordionItem value="category">
                <AccordionTrigger>Category</AccordionTrigger>
                <AccordionContent>
                  <div className="space-y-2">
                    {categories.map((category) => (
                      <div key={category.id} className="flex items-center space-x-2">
                        <Checkbox
                          id={`category-${category.id}`}
                          checked={selectedCategory === category.id}
                          onCheckedChange={() => handleCategoryChange(category.id)}
                        />
                        <Label htmlFor={`category-${category.id}`} className="text-sm font-normal cursor-pointer">
                          {category.label}
                        </Label>
                      </div>
                    ))}
                  </div>
                </AccordionContent>
              </AccordionItem>

              <AccordionItem value="price">
                <AccordionTrigger>Price Range</AccordionTrigger>
                <AccordionContent>
                  <div className="space-y-4">
                    <Slider value={priceRange} min={0} max={1000} step={10} onValueChange={handlePriceChange} />
                    <div className="flex items-center justify-between">
                      <span className="text-sm">${priceRange[0]}</span>
                      <span className="text-sm">${priceRange[1]}</span>
                    </div>
                    <Button size="sm" onClick={handlePriceApply} className="w-full">
                      Apply
                    </Button>
                  </div>
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
