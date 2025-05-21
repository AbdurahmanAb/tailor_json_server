const jsonServer = require("json-server");
const server = jsonServer.create();
const router = jsonServer.router("./db.json");
const middlewares = jsonServer.defaults();
const jwt = require("jsonwebtoken");

// Set default middlewares (logger, static, cors and no-cache)
server.use(middlewares);

// Add custom routes before JSON Server router
server.use(jsonServer.bodyParser);

// JWT secret key
const JWT_SECRET = "your-secret-key";

// Login endpoint
server.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  const users = router.db.get("users").value();
  const user = users.find((u) => u.email === email);

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // In a real app, you would verify the password here
  // For mock purposes, we'll just check if it's not empty
  if (!password) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "1d" });

  // Store token
  const tokens = router.db.get("auth.tokens").value();
  tokens.push({ userId: user.id, token });
  router.db.set("auth.tokens", tokens).write();

  res.json({
    ...user,
    token,
  });
});

// Register endpoint
server.post("/auth/register", (req, res) => {
  const {
    email,
    password,
    name,
    phone,
    location,
    service,
    workType,
    openingTime,
    closingTime,
  } = req.body;
  const users = router.db.get("users").value();

  // Check if user already exists
  if (users.some((u) => u.email === email)) {
    return res.status(400).json({ message: "User already exists" });
  }

  const newUser = {
    id: String(users.length + 1),
    email,
    name,
    photoUrl: null,
    isEmailVerified: false,
    phone,
    location,
    service,
    password,
    workType,
    openingTime,
    closingTime,
    userType: "tailor",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  router.db.get("users").push(newUser).write();

  const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, {
    expiresIn: "1d",
  });

  // Store token
  const tokens = router.db.get("auth.tokens").value();
  tokens.push({ userId: newUser.id, token });
  router.db.set("auth.tokens", tokens).write();

  res.json({
    ...newUser,
    token,
  });
});

// Get current user endpoint
server.get("/auth/me", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const users = router.db.get("users").value();
    const user = users.find((u) => u.id === decoded.userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(user);
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
});

// Logout endpoint
server.post("/auth/logout", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (token) {
    const tokens = router.db.get("auth.tokens").value();
    const newTokens = tokens.filter((t) => t.token !== token);
    router.db.set("auth.tokens", newTokens).write();
  }

  res.json({ message: "Logged out successfully" });
});

// Reset password endpoint
server.post("/auth/reset-password", (req, res) => {
  const { email } = req.body;
  const users = router.db.get("users").value();
  const user = users.find((u) => u.email === email);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  // In a real app, you would send a password reset email here
  res.json({ message: "Password reset email sent" });
});

// Update password endpoint
server.post("/auth/update-password", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { currentPassword, newPassword } = req.body;

    // In a real app, you would verify the current password here
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Invalid password" });
    }

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
});

// Update profile endpoint
server.put("/auth/profile", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const users = router.db.get("users").value();
    const userIndex = users.findIndex((u) => u.id === decoded.userId);

    if (userIndex === -1) {
      return res.status(404).json({ message: "User not found" });
    }

    const updatedUser = {
      ...users[userIndex],
      ...req.body,
      updatedAt: new Date().toISOString(),
    };

    router.db.set(`users[${userIndex}]`, updatedUser).write();
    res.json(updatedUser);
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
});

// Delete account endpoint
server.delete("/auth/account", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const users = router.db.get("users").value();
    const newUsers = users.filter((u) => u.id !== decoded.userId);

    router.db.set("users", newUsers).write();

    // Remove user's tokens
    const tokens = router.db.get("auth.tokens").value();
    const newTokens = tokens.filter((t) => t.userId !== decoded.userId);
    router.db.set("auth.tokens", newTokens).write();

    res.json({ message: "Account deleted successfully" });
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
});

// Use default router
server.use(router);

// Error handling middleware
server.use((err, req, res, next) => {
  console.error(err.stack);

  if (err.name === "JsonWebTokenError") {
    return res.status(401).json({ message: "Invalid token" });
  } else if (err.message === "No token provided") {
    return res.status(401).json({ message: "No token provided" });
  } else if (err.message === "User not found") {
    return res.status(404).json({ message: "User not found" });
  } else if (err.message === "Invalid credentials") {
    return res.status(401).json({ message: "Invalid credentials" });
  } else {
    return res.status(500).json({ message: "Internal server error", details: err.message });
  }
});

const port = 3000;
server.listen(port, () => {
  console.log(`JSON Server is running on port ${port}`);
});
