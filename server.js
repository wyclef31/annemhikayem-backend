require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(cors());
app.use(express.json());

// Railway PORT (kesinlikle böyle olmalı)
const PORT = process.env.PORT || 3000;

// Basit kontrol
app.get("/", (req, res) => res.send("Backend çalışıyor 🚀"));
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    paytrConfigured: !!(process.env.PAYTR_MERCHANT_ID && process.env.PAYTR_MERCHANT_KEY && process.env.PAYTR_MERCHANT_SALT)
  });
});

// PayTR token üretimi (iframe için)
app.post("/paytr/get-token", async (req, res) => {
  try {
    const merchant_id = process.env.PAYTR_MERCHANT_ID;
    const merchant_key = process.env.PAYTR_MERCHANT_KEY;
    const merchant_salt = process.env.PAYTR_MERCHANT_SALT;

    if (!merchant_id || !merchant_key || !merchant_salt) {
      return res.status(500).json({ ok: false, error: "PayTR env bilgileri eksik." });
    }

    const {
      email,
      payment_amount, // KURUŞ (örn 19990)
      user_name,
      user_address,
      user_phone,
      basket_items // [["Ürün", "19990", 1], ...]
    } = req.body;

    if (!email || !payment_amount || !user_name || !user_address || !user_phone) {
      return res.status(400).json({ ok: false, error: "Eksik alan var (email, payment_amount, user_name, user_address, user_phone)." });
    }

    const merchant_oid = "OID_" + Date.now();

    const user_ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "")
      .toString()
      .split(",")[0]
      .trim();

    const test_mode = process.env.PAYTR_TEST_MODE === "true" ? "1" : "0";
    const currency = "TL";
    const no_installment = "0";
    const max_installment = "0";

    const user_basket = Buffer.from(JSON.stringify(basket_items || [["Sipariş", String(payment_amount), 1]])).toString("base64");

    const site_url = process.env.SITE_URL || "";
    const merchant_ok_url = `${site_url}/payment-success.html`;
    const merchant_fail_url = `${site_url}/payment-failure.html`;

    // PayTR hash (standart akış)
    const hashStr =
      merchant_id +
      user_ip +
      merchant_oid +
      email +
      String(payment_amount) +
      user_basket +
      no_installment +
      max_installment +
      currency +
      test_mode +
      merchant_salt;

    const paytr_token = crypto.createHmac("sha256", merchant_key).update(hashStr).digest("base64");

    const postData = {
      merchant_id,
      user_ip,
      merchant_oid,
      email,
      payment_amount: String(payment_amount),
      paytr_token,
      user_basket,
      debug_on: "1",
      no_installment,
      max_installment,
      user_name,
      user_address,
      user_phone,
      merchant_ok_url,
      merchant_fail_url,
      timeout_limit: "30",
      currency,
      test_mode,
      lang: "tr"
    };

    const r = await axios.post("https://www.paytr.com/odeme/api/get-token", postData, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      transformRequest: [(data) => new URLSearchParams(data).toString()]
    });

    if (r.data?.status !== "success") {
      return res.status(400).json({ ok: false, error: r.data?.reason || "PayTR token alınamadı", raw: r.data });
    }

    return res.json({ ok: true, token: r.data.token, merchant_oid });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || "Server error" });
  }
});

// PayTR callback (PayTR panelindeki Bildirim URL buraya gelmeli)
app.post("/paytr/callback", express.urlencoded({ extended: false }), (req, res) => {
  // Burada hash doğrulama + sipariş kaydı yapılır.
  // Şimdilik PayTR'ye OK dönmek yeterli (yoksa tekrar tekrar dener).
  console.log("PayTR callback geldi:", req.body);
  res.send("OK");
});

app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
