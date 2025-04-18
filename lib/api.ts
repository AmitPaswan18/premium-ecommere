// API functions to interact with the Fake Store API

// Get all products
export async function getProducts() {
  try {
    const response = await fetch("https://fakestoreapi.com/products")
    if (!response.ok) {
      throw new Error("Failed to fetch products")
    }
    return response.json()
  } catch (error) {
    console.error("Error fetching products:", error)
    return []
  }
}

// Get a single product by ID
export async function getProductById(id) {
  try {
    const response = await fetch(`https://fakestoreapi.com/products/${id}`)
    if (!response.ok) {
      throw new Error("Failed to fetch product")
    }
    return response.json()
  } catch (error) {
    console.error(`Error fetching product with ID ${id}:`, error)
    return null
  }
}

// Get all categories
export async function getCategories() {
  try {
    const response = await fetch("https://fakestoreapi.com/products/categories")
    if (!response.ok) {
      throw new Error("Failed to fetch categories")
    }
    return response.json()
  } catch (error) {
    console.error("Error fetching categories:", error)
    return []
  }
}

// Get all products in a specific category
export async function getProductsByCategory(category) {
  try {
    const response = await fetch(`https://fakestoreapi.com/products/category/${category}`)
    if (!response.ok) {
      throw new Error("Failed to fetch products by category")
    }
    return response.json()
  } catch (error) {
    console.error(`Error fetching products in category ${category}:`, error)
    return []
  }
}

// Get all users
export async function getUsers() {
  try {
    const response = await fetch("https://fakestoreapi.com/users")
    if (!response.ok) {
      throw new Error("Failed to fetch users")
    }
    return response.json()
  } catch (error) {
    console.error("Error fetching users:", error)
    return []
  }
}

// Get all carts
export async function getCarts() {
  try {
    const response = await fetch("https://fakestoreapi.com/carts")
    if (!response.ok) {
      throw new Error("Failed to fetch carts")
    }
    return response.json()
  } catch (error) {
    console.error("Error fetching carts:", error)
    return []
  }
}

// Get a user's cart
export async function getUserCart(userId) {
  try {
    const response = await fetch(`https://fakestoreapi.com/carts/user/${userId}`)
    if (!response.ok) {
      throw new Error("Failed to fetch user cart")
    }
    return response.json()
  } catch (error) {
    console.error(`Error fetching cart for user ${userId}:`, error)
    return []
  }
}

// Create a new order (mock function since the API doesn't support this)
export async function createOrder(orderData) {
  // In a real app, this would be a POST request to your backend
  console.log("Creating order with data:", orderData)

  // Simulate API delay
  await new Promise((resolve) => setTimeout(resolve, 1000))

  // Return a mock response
  return {
    id: `ORD-${Math.floor(Math.random() * 10000)}-${Date.now().toString().slice(-4)}`,
    ...orderData,
    status: "processing",
    createdAt: new Date().toISOString(),
  }
}

// Get user orders (mock function)
export async function getUserOrders(userId) {
  // In a real app, this would be a GET request to your backend
  console.log("Fetching orders for user:", userId)

  // Simulate API delay
  await new Promise((resolve) => setTimeout(resolve, 1000))

  // Return mock orders
  return [
    {
      id: `ORD-1234-${Date.now().toString().slice(-4)}`,
      userId,
      products: [
        { productId: 1, quantity: 2 },
        { productId: 3, quantity: 1 },
      ],
      total: 129.99,
      status: "delivered",
      date: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
    },
    {
      id: `ORD-5678-${Date.now().toString().slice(-4)}`,
      userId,
      products: [{ productId: 2, quantity: 1 }],
      total: 55.99,
      status: "processing",
      date: new Date().toISOString(),
    },
  ]
}
