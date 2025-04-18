import { type NextRequest, NextResponse } from "next/server"
import { getToken } from "next-auth/jwt"

// Define public routes that don't require authentication
const publicRoutes = ["/signin", "/api/auth"]

export async function middleware(req: NextRequest) {
    const path = req.nextUrl.pathname

    // Check if the path is a public route or starts with a public route prefix
    const isPublicRoute = publicRoutes.some((route) => path === route || path.startsWith(`${route}/`))

    // Allow access to public routes and Next.js resources
    if (isPublicRoute || path.startsWith("/_next") || path.includes("/api/auth")) {
        return NextResponse.next()
    }

    // Get the session token
    const token = await getToken({
        req,
        secret: "c8130054f85f36d9b2f7fbed8f0d43d9b9b47b9f9e9c6d8a7f6e5d4c3b2a1b0a", // Use the same hardcoded secret as in your auth config
    })

    // If there's no token and the route is not public, redirect to signin
    if (!token) {
        const url = new URL("/signin", req.url)
        url.searchParams.set("callbackUrl", encodeURI(req.url))
        return NextResponse.redirect(url)
    }

    // Allow access if authenticated
    return NextResponse.next()
}

// Configure which routes the middleware should run on
export const config = {
    matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
}
