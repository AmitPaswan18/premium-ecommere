import NextAuth from "next-auth"
import CredentialsProvider from "next-auth/providers/credentials"
import type { NextAuthOptions } from "next-auth"

export const authOptions: NextAuthOptions = {
    providers: [
        CredentialsProvider({
            name: "Credentials",
            credentials: {
                email: { label: "Email", type: "email" },
                password: { label: "Password", type: "password" },
            },
            async authorize(credentials) {
                // This is where you would typically verify the user credentials against your database
                // For demo purposes, we're using a hardcoded user
                // In a real application, you would check against your database
                if (credentials?.email === "user@example.com" && credentials?.password === "password") {
                    return {
                        id: "1",
                        name: "Demo User",
                        email: "user@example.com",
                    }
                }

                // For debugging purposes, let's accept any credentials temporarily
                // Remove this in production!
                return {
                    id: "2",
                    name: "Test User",
                    email: credentials?.email || "test@example.com",
                }
            },
        }),
    ],
    pages: {
        signIn: "/signin",
    },
    session: {
        strategy: "jwt",
        maxAge: 30 * 24 * 60 * 60, // 30 days
    },
    callbacks: {
        async jwt({ token, user }) {
            if (user) {
                token.id = user.id
            }
            return token
        },
        async session({ session, token }) {
            if (session.user) {
                session.user.id = token.id as string
            }
            return session
        },
    },
    debug: true, // Enable debug mode for development
    secret: "QerWODGJwcJF/Hf1z01PrcIyKGrhDX5IXawaFjWHyu8=", // Using the provided secret
}

const handler = NextAuth(authOptions)
export { handler as GET, handler as POST }
