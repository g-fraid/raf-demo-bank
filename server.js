const express = require("express");
const session = require("express-session");
const path = require("path");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const User = require("./models/User");

const app = express();
const PORT = 3000;
const HOST = "0.0.0.0";
const MONGO_URI = "mongodb://localhost:27017/nosql_demo_bank";

// --- Database connection ---
mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");
    seedUsersIfEmpty();
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err);
  });

// --- View engine and static assets ---
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// --- Session configuration ---
app.use(
  session({
    secret: "raf-demo-bank-session-secret",
    resave: false,
    saveUninitialized: false,
  })
);

// --- Current user helper ---
app.use(async (req, res, next) => {
  if (req.session.userId) {
    try {
      const user = await User.findById(req.session.userId);
      req.currentUser = user || null;
      res.locals.currentUser = user || null;
    } catch (e) {
      req.currentUser = null;
      res.locals.currentUser = null;
    }
  } else {
    req.currentUser = null;
    res.locals.currentUser = null;
  }
  next();
});

function requireAuth(req, res, next) {
  if (!req.currentUser) {
    return res.redirect("/login");
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.currentUser || req.currentUser.role !== "admin") {
    return res.status(403).send("Access denied");
  }
  next();
}

// --- Routes ---

app.get("/", (req, res) => {
  if (req.currentUser) {
    return res.redirect("/profile");
  }
  return res.redirect("/login");
});

app.get("/login", (req, res) => {
  if (req.currentUser) {
    return res.redirect("/profile");
  }
  res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  // Note: password is stored in plaintext for simplicity in this lab setup.
  if (!user || user.password !== password) {
    return res.status(401).render("login", {
      error: "Невірний логін або пароль",
    });
  }

  req.session.userId = user._id.toString();
  res.redirect("/profile");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.get("/profile", requireAuth, (req, res) => {
  res.render("profile", { user: req.currentUser });
});

app.get("/dashboard", requireAuth, requireAdmin, async (req, res) => {
  const users = await User.find({});
  res.render("dashboard", { users });
});

// --- Vulnerable transfer API (HMAC + NoSQL injection) ---
app.post("/api/transfer", async (req, res) => {
  const { senderIban, receiverIban, amount, signature } = req.body;

  if (!senderIban || !receiverIban || !amount || !signature) {
    return res.status(400).json({
      success: false,
      error: "Відсутні обовʼязкові поля запиту",
    });
  }

  const numericAmount = Number(amount);
  if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
    return res.status(400).json({
      success: false,
      error: "Некоректна сума переказу",
    });
  }

  const sender = await User.findOne({ iban: senderIban });
  if (!sender) {
    return res.status(400).json({
      success: false,
      error: "Відправника не знайдено",
    });
  }

  // Build canonical JSON payload for HMAC calculation.
  // This mirrors what a legitimate client would do.
  const payloadObject = {
    senderIban: String(senderIban),
    receiverIban: receiverIban,
    amount: numericAmount,
  };

  const payloadJson = JSON.stringify(payloadObject);

  // HMAC-SHA256 over JSON payload using user's secret as key.
  const expectedSignature = crypto
    .createHmac("sha256", sender.hmacSecret)
    .update(payloadJson)
    .digest("hex");

  if (typeof signature !== "string" || signature.toLowerCase() !== expectedSignature.toLowerCase()) {
    return res.status(403).json({
      success: false,
      error: "Некоректний HMAC-підпис",
    });
  }

  // If receiverIban is a string, treat it as a normal IBAN lookup.
  // If it is an object, it is used directly as a MongoDB filter.
  // This allows very flexible matching, but also opens the door
  // to NoSQL injection if the client is not fully trusted.
  let receiverQuery;

  if (typeof receiverIban === "string") {
    receiverQuery = { iban: receiverIban };
  } else if (receiverIban && typeof receiverIban === "object") {
    receiverQuery = receiverIban;
  } else {
    return res.status(400).json({
      success: false,
      error: "Некоректний формат поля receiverIban",
    });
  }

  const receiver = await User.findOne(receiverQuery);

  if (!receiver) {
    // For blind exploitation this "not found" branch acts as a boolean signal.
    return res.status(400).json({
      success: false,
      error: "Отримувача не знайдено",
    });
  }

  if (sender.balance < numericAmount) {
    return res.status(400).json({
      success: false,
      error: "Недостатньо коштів на рахунку",
    });
  }

  sender.balance -= numericAmount;
  receiver.balance += numericAmount;

  await sender.save();
  await receiver.save();

  // No detailed receiver data is returned here.
  // The attacker only sees success/failure and must infer data indirectly.
  return res.json({
    success: true,
    message: "Переказ виконано успішно",
    sender: {
      iban: sender.iban,
      balance: sender.balance,
    },
  });
});

// --- Start server ---
app.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
});

// --- Seed users ---

function randomHmacSecret() {
  return crypto.randomBytes(32).toString("hex");
}

function randomUahBalance(min = 1000, max = 100000) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIban() {
  const digits = Array.from({ length: 27 }, () =>
    Math.floor(Math.random() * 10)
  ).join("");
  return "UA" + digits;
}

async function seedUsersIfEmpty() {
  const count = await User.countDocuments();
  if (count > 0) {
    console.log("Users already exist, skip seeding");
    return;
  }

  console.log("Seeding initial users for Raf Demo Bank...");

  const baseUsers = [
    {
      username: "admin",
      firstName: "Admin",
      lastName: "Raf",
      middleName: "Supervisor",
      role: "admin",
      password: "RafAdminLatte!",
    },
    {
      username: "ipetrenko",
      firstName: "Ivan",
      lastName: "Petrenko",
      middleName: "Olehovych",
      role: "user",
      password: "GreenForest!",
    },
    {
      username: "oshevchenko",
      firstName: "Olena",
      lastName: "Shevchenko",
      middleName: "Serhiivna",
      role: "user",
      password: "SilverBook!",
    },
    {
      username: "tkoval",
      firstName: "Taras",
      lastName: "Koval",
      middleName: "Andriiovych",
      role: "user",
      password: "MorningTram!",
    },
    {
      username: "nbondarenko",
      firstName: "Nazar",
      lastName: "Bondarenko",
      middleName: "Stepanovych",
      role: "user",
      password: "OceanBridge!",
    },
    {
      username: "imelnyk",
      firstName: "Iryna",
      lastName: "Melnyk",
      middleName: "Volodymyrivna",
      role: "user",
      password: "GoldenGarden!",
    },
    {
      username: "dkravets",
      firstName: "Dmytro",
      lastName: "Kravets",
      middleName: "Oleksandrovych",
      role: "user",
      password: "AutumnCoffee!",
    },
    {
      username: "slisova",
      firstName: "Sofiia",
      lastName: "Lisova",
      middleName: "Mykhailivna",
      role: "user",
      password: "QuietStreet!",
    },
    {
      username: "ahorobets",
      firstName: "Andrii",
      lastName: "Horobets",
      middleName: "Ihorovych",
      role: "user",
      password: "SoftCloud!",
    },
    {
      username: "mchernenko",
      firstName: "Mariia",
      lastName: "Chernenko",
      middleName: "Oleksiivna",
      role: "user",
      password: "SunnyRiver!",
    },
  ];

  const usersToInsert = baseUsers.map((u) => ({
    username: u.username,
    password: u.password,
    firstName: u.firstName,
    lastName: u.lastName,
    middleName: u.middleName,
    role: u.role,
    iban: randomIban(),
    balance: randomUahBalance(),
    hmacSecret: randomHmacSecret(),
  }));

  await User.insertMany(usersToInsert);
  console.log("Users seeded");
}
