const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // plaintext in this lab setup
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  middleName: { type: String, required: true },
  iban: { type: String, required: true, unique: true },
  balance: { type: Number, required: true, default: 0 },
  hmacSecret: { type: String, required: true },
  role: { type: String, enum: ["admin", "user"], default: "user" },
}, { timestamps: true });

module.exports = mongoose.model("User", userSchema);
