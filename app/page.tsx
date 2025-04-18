import { Suspense } from "react";
import Hero from "@/components/hero";
import FeaturedProducts from "@/components/featured-products";
import Categories from "@/components/categories";
import Newsletter from "@/components/newsletter";
import { ProductSkeleton } from "@/components/skeletons";
import { getServerSession } from "next-auth/next";
import { authOptions } from "./api/auth/[...nextauth]/route";
import { redirect } from "next/navigation";

export default async function Home() {
  const session = await getServerSession(authOptions);

  if (!session) {
    redirect("/signin");
  }
  return (
    <div className="container mx-auto px-4 py-8">
      <Hero />
      <Categories />
      <section className="my-16">
        <h2 className="text-3xl font-bold mb-8 text-center">
          Featured Products
        </h2>
        <Suspense fallback={<ProductSkeleton count={4} />}>
          <FeaturedProducts />
        </Suspense>
      </section>
      <Newsletter />
    </div>
  );
}
