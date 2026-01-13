/**
 * İyzico ve PayTR Ödeme Sunucusu
 * 
 * Bu sunucu, frontend'den gelen ödeme isteklerini işler ve
 * İyzico ve PayTR API'leri ile iletişim kurar.
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const iyzipay = require('iyzipay');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
// CORS ayarları - Firebase Hosting ve custom domain'leri dahil et
const allowedOrigins = [
    'http://localhost:5500',
    'http://localhost:3000',
    'https://annemhikayem-38c31.web.app',
    'https://annemhikayem-38c31.firebaseapp.com',
    'https://annemhikayem.com.tr',
    'https://www.annemhikayem.com.tr',
    process.env.FRONTEND_URL
].filter(Boolean); // undefined değerleri temizle

app.use(cors({
    origin: function (origin, callback) {
        // Origin yoksa (mobile app, Postman vb.) veya izin verilen listede varsa kabul et
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            // Geliştirme için tüm origin'lere izin ver (production'da kaldırılabilir)
            if (process.env.NODE_ENV !== 'production') {
                callback(null, true);
            } else {
                callback(new Error('CORS policy: Origin not allowed'));
            }
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files (payment sayfaları için)
app.use(express.static(path.join(__dirname)));

// İyzico yapılandırması
const iyzicoConfig = {
    apiKey: process.env.IYZICO_API_KEY,
    secretKey: process.env.IYZICO_SECRET_KEY,
    uri: process.env.IYZICO_MODE === 'production' 
        ? 'https://api.iyzipay.com' 
        : 'https://sandbox-api.iyzipay.com'
};

// İyzico client oluştur
const iyzicoClient = new iyzipay(iyzicoConfig);

// PayTR yapılandırması
const paytrConfig = {
    merchantId: process.env.PAYTR_MERCHANT_ID,
    merchantKey: process.env.PAYTR_MERCHANT_KEY,
    merchantSalt: process.env.PAYTR_MERCHANT_SALT,
    testMode: process.env.PAYTR_TEST_MODE === 'true',
    apiUrl: process.env.PAYTR_TEST_MODE === 'true'
        ? 'https://www.paytr.com/odeme/test-gonder'
        : 'https://www.paytr.com/odeme/api/get-token'
};

// PayTR hash oluşturma fonksiyonu
function createPaytrHash(data) {
    const hashString = Object.keys(data)
        .sort()
        .map(key => `${key}=${data[key]}`)
        .join('&');
    return crypto.createHmac('sha256', paytrConfig.merchantSalt)
        .update(hashString)
        .digest('base64');
}

/**
 * POST /api/payment/create
 * 
 * Ödeme formu oluşturur (iyzico)
 * 
 * Body:
 * - basketItems: Sepetteki ürünler
 * - buyer: Müşteri bilgileri
 * - shippingAddress: Kargo adresi (fiziksel ürünler için zorunlu)
 * - totalPrice: Toplam fiyat
 * - paymentProvider: Şimdilik sadece 'iyzico' kullanılıyor (varsayılan: 'iyzico')
 */
app.post('/api/payment/create', async (req, res) => {
    // Şimdilik sadece iyzico kullanılıyor
    const { paymentProvider = 'iyzico' } = req.body;
    
    // PayTR desteği geçici olarak devre dışı
    if (paymentProvider === 'paytr') {
        return res.status(400).json({
            error: 'PayTR desteği şu anda aktif değil',
            details: 'Lütfen iyzico ile ödeme yapın'
        });
    }
    
    // Varsayılan olarak iyzico kullan
    return handleIyzicoPayment(req, res);
});

/**
 * İyzico ödeme işlemi
 */
function handleIyzicoPayment(req, res) {
    try {
        // Input validation
        const validationErrors = validatePaymentRequest(req.body);
        if (validationErrors.length > 0) {
            logPayment('warning', 'iyzico', 'validation_failed', {
                action: 'payment_create',
                errors: validationErrors,
                ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
            });
            return res.status(400).json({ 
                error: 'Geçersiz istek',
                details: validationErrors
            });
        }

        const { basketItems, buyer, shippingAddress, totalPrice, requiresShipping } = req.body;

        // Fiziksel ürün varsa kargo adresi zorunlu
        if (requiresShipping && (!shippingAddress || !shippingAddress.address)) {
            return res.status(400).json({ 
                error: 'Kargo adresi gereklidir' 
            });
        }

        // Benzersiz sipariş ID oluştur
        const conversationId = 'ORDER_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        
        // Loglama
        logPayment('info', 'iyzico', conversationId, {
            action: 'payment_create',
            buyer: buyer.email,
            totalPrice: totalPrice,
            ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
        });

        // Sepet öğelerini İyzico formatına dönüştür
        const basketItemsFormatted = basketItems.map((item, index) => ({
            id: item.id || `ITEM_${index + 1}`,
            name: item.name.substring(0, 127), // İyzico limiti
            category1: 'Ürün',
            category2: 'Genel',
            itemType: 'PHYSICAL',
            price: parseFloat(item.price) * parseInt(item.quantity)
        }));

        // Fatura adresi (kargo adresi varsa onu kullan, yoksa buyer bilgilerini kullan)
        const billingAddress = shippingAddress && shippingAddress.address ? {
            contactName: `${buyer.name} ${buyer.surname}`,
            city: shippingAddress.city || 'Istanbul',
            country: 'Turkey',
            address: shippingAddress.address.substring(0, 200), // İyzico limiti
            zipCode: shippingAddress.postalCode || '34000'
        } : {
            contactName: `${buyer.name} ${buyer.surname}`,
            city: 'Istanbul',
            country: 'Turkey',
            address: 'Bilgi verilmedi',
            zipCode: '34000'
        };

        // Kargo adresi (fiziksel ürünler için)
        const shippingAddressFormatted = requiresShipping && shippingAddress ? {
            contactName: `${buyer.name} ${buyer.surname}`,
            city: shippingAddress.city || 'Istanbul',
            country: 'Turkey',
            address: shippingAddress.address.substring(0, 200),
            zipCode: shippingAddress.postalCode || '34000'
        } : null;

        // Callback URL oluştur (environment variable veya request'ten)
        const callbackUrl = process.env.CALLBACK_URL || `${req.protocol}://${req.get('host')}/api/payment/callback`;
        
        // İyzico ödeme isteği oluştur
        const paymentRequest = {
            locale: 'tr',
            conversationId: conversationId,
            price: totalPrice.toFixed(2),
            paidPrice: totalPrice.toFixed(2),
            currency: 'TRY',
            installment: '1',
            basketId: 'BASKET_' + Date.now(),
            paymentChannel: 'WEB',
            paymentGroup: 'PRODUCT',
            callbackUrl: callbackUrl,
            enabledInstallments: [2, 3, 6, 9],
            buyer: {
                id: 'BY' + Date.now(),
                name: buyer.name,
                surname: buyer.surname,
                gsmNumber: buyer.phone,
                email: buyer.email,
                identityNumber: '11111111111', // Test için
                lastLoginDate: new Date().toISOString(),
                registrationDate: new Date().toISOString(),
                registrationAddress: billingAddress.address,
                ip: req.ip || '127.0.0.1',
                city: billingAddress.city,
                country: billingAddress.country,
                zipCode: billingAddress.zipCode
            },
            shippingAddress: shippingAddressFormatted || billingAddress,
            billingAddress: billingAddress,
            basketItems: basketItemsFormatted
        };

        // İyzico'ya istek gönder
        iyzicoClient.checkoutFormInitialize.create(paymentRequest, (err, result) => {
            if (err) {
                console.error('İyzico ödeme oluşturma hatası:', err);
                logPayment('error', 'iyzico', conversationId, {
                    action: 'payment_create_error',
                    error: err.message,
                    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
                });
                return res.status(500).json({ 
                    error: 'Ödeme oluşturulurken bir hata oluştu',
                    details: err.message 
                });
            }

            if (result.status === 'success') {
                // Başarılı - checkout form content döndür
                logPayment('success', 'iyzico', conversationId, {
                    action: 'payment_created',
                    paymentPageUrl: result.paymentPageUrl,
                    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
                });
                res.json({
                    success: true,
                    checkoutFormContent: result.checkoutFormContent,
                    paymentPageUrl: result.paymentPageUrl,
                    conversationId: conversationId
                });
            } else {
                console.error('İyzico ödeme oluşturma hatası:', result.errorMessage);
                logPayment('error', 'iyzico', conversationId, {
                    action: 'payment_create_failed',
                    error: result.errorMessage,
                    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
                });
                res.status(400).json({
                    error: 'Ödeme oluşturulamadı',
                    details: result.errorMessage || 'Bilinmeyen hata'
                });
            }
        });

    } catch (error) {
        console.error('Sunucu hatası:', error);
        res.status(500).json({ 
            error: 'Sunucu hatası',
            details: error.message 
        });
    }
}

/**
 * PayTR ödeme işlemi
 */
async function handlePaytrPayment(req, res) {
    try {
        // Input validation
        const validationErrors = validatePaymentRequest(req.body);
        if (validationErrors.length > 0) {
            logPayment('warning', 'paytr', 'validation_failed', {
                action: 'payment_create',
                errors: validationErrors,
                ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
            });
            return res.status(400).json({ 
                error: 'Geçersiz istek',
                details: validationErrors
            });
        }

        const { basketItems, buyer, shippingAddress, totalPrice, requiresShipping } = req.body;

        // Benzersiz sipariş ID oluştur
        const merchantOid = 'ORDER_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        
        // Loglama
        logPayment('info', 'paytr', merchantOid, {
            action: 'payment_create',
            buyer: buyer.email,
            totalPrice: totalPrice,
            ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
        });

        // Sepet öğelerini formatla
        const basketItemsFormatted = basketItems.map((item, index) => ({
            name: item.name.substring(0, 127),
            price: (parseFloat(item.price) * parseInt(item.quantity)).toFixed(2)
        }));

        // Callback URL oluştur
        const callbackUrl = process.env.CALLBACK_URL || `${req.protocol}://${req.get('host')}/api/payment/callback-paytr`;
        const failUrl = `${req.protocol}://${req.get('host')}/payment-failure.html`;

        // PayTR ödeme isteği verileri
        const paytrData = {
            merchant_id: paytrConfig.merchantId,
            user_ip: req.ip || req.headers['x-forwarded-for'] || '127.0.0.1',
            merchant_oid: merchantOid,
            email: buyer.email,
            payment_amount: (totalPrice * 100).toFixed(0), // Kuruş cinsinden
            paytr_token: '',
            user_basket: Buffer.from(JSON.stringify(basketItemsFormatted)).toString('base64'),
            debug_on: paytrConfig.testMode ? '1' : '0',
            no_installment: '0',
            max_installment: '0',
            user_name: buyer.name,
            user_address: shippingAddress && shippingAddress.address 
                ? `${shippingAddress.address}, ${shippingAddress.district}, ${shippingAddress.city}`
                : 'Bilgi verilmedi',
            user_phone: buyer.phone.replace(/\s/g, ''),
            merchant_ok_url: `${req.protocol}://${req.get('host')}/payment-success.html`,
            merchant_fail_url: failUrl,
            timeout_limit: '30',
            currency: 'TL',
            lang: 'tr'
        };

        // Hash oluştur
        paytrData.paytr_token = createPaytrHash(paytrData);

        // PayTR API'ye istek gönder
        const https = require('https');
        const querystring = require('querystring');

        const postData = querystring.stringify(paytrData);

        const options = {
            hostname: 'www.paytr.com',
            port: 443,
            path: paytrConfig.testMode ? '/odeme/test-gonder' : '/odeme/api/get-token',
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const paytrRequest = https.request(options, (paytrResponse) => {
            let data = '';

            paytrResponse.on('data', (chunk) => {
                data += chunk;
            });

            paytrResponse.on('end', () => {
                try {
                    const result = JSON.parse(data);

                    if (result.status === 'success') {
                        // Başarılı - token döndür
                        logPayment('success', 'paytr', merchantOid, {
                            action: 'payment_created',
                            token: result.token,
                            ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
                        });
                        res.json({
                            success: true,
                            paymentProvider: 'paytr',
                            token: result.token,
                            merchantOid: merchantOid,
                            iframeUrl: `https://www.paytr.com/odeme/guvenli/${result.token}`
                        });
                    } else {
                        console.error('PayTR ödeme oluşturma hatası:', result.reason);
                        logPayment('error', 'paytr', merchantOid, {
                            action: 'payment_create_failed',
                            error: result.reason,
                            ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
                        });
                        res.status(400).json({
                            error: 'Ödeme oluşturulamadı',
                            details: result.reason || 'Bilinmeyen hata'
                        });
                    }
                } catch (error) {
                    console.error('PayTR yanıt parse hatası:', error);
                    res.status(500).json({
                        error: 'PayTR yanıtı işlenemedi',
                        details: error.message
                    });
                }
            });
        });

        paytrRequest.on('error', (error) => {
            console.error('PayTR istek hatası:', error);
            res.status(500).json({
                error: 'PayTR sunucusuna bağlanılamadı',
                details: error.message
            });
        });

        paytrRequest.write(postData);
        paytrRequest.end();

    } catch (error) {
        console.error('PayTR sunucu hatası:', error);
        res.status(500).json({ 
            error: 'Sunucu hatası',
            details: error.message 
        });
    }
}

/**
 * POST /api/payment/callback
 * 
 * İyzico'dan gelen ödeme sonuç callback'ini işler
 */
app.post('/api/payment/callback', async (req, res) => {
    try {
        const token = req.body.token;

        if (!token) {
            return res.redirect('/payment-failure.html?error=token_missing');
        }

        // Ödeme sonucunu sorgula
        const request = {
            locale: 'tr',
            token: token
        };

        iyzicoClient.checkoutForm.retrieve(request, (err, result) => {
            if (err) {
                console.error('Ödeme sorgulama hatası:', err);
                return res.redirect('/payment-failure.html?error=query_failed');
            }

            if (result.status === 'success' && result.paymentStatus === 'SUCCESS') {
                // Ödeme başarılı - başarı sayfasına yönlendir
                logPayment('success', 'iyzico', result.conversationId || 'unknown', {
                    action: 'payment_success',
                    paymentId: result.paymentId,
                    paidPrice: result.paidPrice,
                    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
                });
                const queryParams = new URLSearchParams({
                    conversationId: result.conversationId || '',
                    paymentId: result.paymentId || '',
                    price: result.paidPrice || '0'
                });
                res.redirect(`/payment-success.html?${queryParams.toString()}`);
            } else {
                // Ödeme başarısız - hata sayfasına yönlendir
                const errorMessage = result.errorMessage || 'Ödeme işlemi başarısız oldu';
                logPayment('error', 'iyzico', result.conversationId || 'unknown', {
                    action: 'payment_failed',
                    error: errorMessage,
                    ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
                });
                const queryParams = new URLSearchParams({
                    error: errorMessage
                });
                res.redirect(`/payment-failure.html?${queryParams.toString()}`);
            }
        });

    } catch (error) {
        console.error('Callback hatası:', error);
        res.redirect('/payment-failure.html?error=server_error');
    }
});

/**
 * POST /api/payment/callback-paytr
 * 
 * PayTR'den gelen ödeme sonuç callback'ini işler
 */
app.post('/api/payment/callback-paytr', async (req, res) => {
    try {
        const { merchant_oid, status, total_amount, hash } = req.body;

        if (!merchant_oid || !status || !total_amount || !hash) {
            return res.redirect('/payment-failure.html?error=invalid_callback');
        }

        // Hash doğrulama
        const hashString = `${paytrConfig.merchantId}${merchant_oid}${paytrConfig.merchantSalt}${status}${total_amount}`;
        const calculatedHash = crypto.createHmac('sha256', paytrConfig.merchantKey)
            .update(hashString)
            .digest('base64');

        if (calculatedHash !== hash) {
            console.error('PayTR hash doğrulama hatası');
            return res.redirect('/payment-failure.html?error=hash_verification_failed');
        }

        if (status === 'success') {
            // Ödeme başarılı
            logPayment('success', 'paytr', merchant_oid, {
                action: 'payment_success',
                totalAmount: total_amount,
                ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
            });
            const queryParams = new URLSearchParams({
                conversationId: merchant_oid,
                paymentId: merchant_oid,
                price: (parseFloat(total_amount) / 100).toFixed(2) // Kuruştan liraya çevir
            });
            res.redirect(`/payment-success.html?${queryParams.toString()}`);
        } else {
            // Ödeme başarısız
            const errorMessage = req.body.failed_reason_code || 'Ödeme işlemi başarısız oldu';
            logPayment('error', 'paytr', merchant_oid, {
                action: 'payment_failed',
                error: errorMessage,
                ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
            });
            const queryParams = new URLSearchParams({
                error: errorMessage
            });
            res.redirect(`/payment-failure.html?${queryParams.toString()}`);
        }

    } catch (error) {
        console.error('PayTR callback hatası:', error);
        res.redirect('/payment-failure.html?error=server_error');
    }
});

/**
 * POST /api/payment/webhook-iyzico
 * 
 * İyzico webhook endpoint'i (asenkron bildirimler için)
 */
app.post('/api/payment/webhook-iyzico', async (req, res) => {
    try {
        const { eventType, paymentId, conversationId, status } = req.body;

        console.log('İyzico webhook alındı:', {
            eventType,
            paymentId,
            conversationId,
            status,
            timestamp: new Date().toISOString()
        });

        // Webhook verilerini logla veya veritabanına kaydet
        // TODO: Firebase Firestore'a webhook log kaydet

        res.status(200).json({ received: true });
    } catch (error) {
        console.error('İyzico webhook hatası:', error);
        res.status(500).json({ error: 'Webhook işlenemedi' });
    }
});

/**
 * POST /api/payment/webhook-paytr
 * 
 * PayTR webhook endpoint'i (asenkron bildirimler için)
 */
app.post('/api/payment/webhook-paytr', async (req, res) => {
    try {
        const { merchant_oid, status, total_amount, hash } = req.body;

        console.log('PayTR webhook alındı:', {
            merchant_oid,
            status,
            total_amount,
            timestamp: new Date().toISOString()
        });

        // Hash doğrulama
        if (hash) {
            const hashString = `${paytrConfig.merchantId}${merchant_oid}${paytrConfig.merchantSalt}${status}${total_amount}`;
            const calculatedHash = crypto.createHmac('sha256', paytrConfig.merchantKey)
                .update(hashString)
                .digest('base64');

            if (calculatedHash !== hash) {
                console.error('PayTR webhook hash doğrulama hatası');
                return res.status(400).json({ error: 'Hash doğrulama başarısız' });
            }
        }

        // Webhook verilerini logla veya veritabanına kaydet
        // TODO: Firebase Firestore'a webhook log kaydet

        res.status(200).json({ received: true });
    } catch (error) {
        console.error('PayTR webhook hatası:', error);
        res.status(500).json({ error: 'Webhook işlenemedi' });
    }
});

/**
 * GET /api/payment/status/:orderId
 * 
 * Ödeme durumunu sorgular
 */
app.get('/api/payment/status/:orderId', async (req, res) => {
    try {
        const { orderId } = req.params;
        const { provider = 'iyzico' } = req.query;

        if (provider === 'paytr') {
            // PayTR için ödeme sorgulama (gerekirse)
            res.json({
                orderId,
                provider: 'paytr',
                message: 'PayTR ödeme durumu sorgulama için merchant panelini kullanın'
            });
        } else {
            // İyzico için ödeme sorgulama
            const request = {
                locale: 'tr',
                conversationId: orderId
            };

            iyzicoClient.payment.retrieve(request, (err, result) => {
                if (err) {
                    return res.status(500).json({
                        error: 'Ödeme sorgulanamadı',
                        details: err.message
                    });
                }

                res.json({
                    orderId,
                    provider: 'iyzico',
                    status: result.status,
                    paymentStatus: result.paymentStatus,
                    paidPrice: result.paidPrice,
                    currency: result.currency
                });
            });
        }
    } catch (error) {
        console.error('Ödeme durumu sorgulama hatası:', error);
        res.status(500).json({
            error: 'Sunucu hatası',
            details: error.message
        });
    }
});

/**
 * POST /api/payment/refund
 * 
 * İade işlemi (iyzico için)
 */
app.post('/api/payment/refund', async (req, res) => {
    try {
        const { paymentId, price, currency = 'TRY', reason = 'İade talebi' } = req.body;

        if (!paymentId || !price) {
            return res.status(400).json({
                error: 'Ödeme ID ve tutar gereklidir'
            });
        }

        const request = {
            locale: 'tr',
            conversationId: 'REFUND_' + Date.now(),
            paymentTransactionId: paymentId,
            price: parseFloat(price).toFixed(2),
            currency: currency,
            ip: req.ip || '127.0.0.1'
        };

        iyzicoClient.refund.create(request, (err, result) => {
            if (err) {
                console.error('İade işlemi hatası:', err);
                return res.status(500).json({
                    error: 'İade işlemi başarısız',
                    details: err.message
                });
            }

            if (result.status === 'success') {
                res.json({
                    success: true,
                    refundId: result.paymentId,
                    refundPrice: result.price,
                    status: result.status
                });
            } else {
                res.status(400).json({
                    error: 'İade işlemi başarısız',
                    details: result.errorMessage || 'Bilinmeyen hata'
                });
            }
        });
    } catch (error) {
        console.error('İade sunucu hatası:', error);
        res.status(500).json({
            error: 'Sunucu hatası',
            details: error.message
        });
    }
});

/**
 * Ödeme işlemlerini loglama fonksiyonu
 */
function logPayment(level, provider, orderId, data) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        level: level, // 'info', 'error', 'success', 'warning'
        provider: provider, // 'iyzico', 'paytr'
        orderId: orderId,
        data: data,
        ip: data.ip || 'unknown'
    };

    // Console'a log
    console.log(`[${level.toUpperCase()}] [${provider}] [${orderId}]`, logEntry);

    // TODO: Burada logları veritabanına veya log dosyasına kaydedebilirsiniz
    // Örnek: Firebase Firestore'a log kaydet
    // db.collection('payment_logs').add(logEntry);
}

/**
 * Input validation fonksiyonu
 */
function validatePaymentRequest(body) {
    const errors = [];

    // Basket items kontrolü
    if (!body.basketItems || !Array.isArray(body.basketItems) || body.basketItems.length === 0) {
        errors.push('Sepet boş olamaz');
    }

    // Buyer bilgileri kontrolü
    if (!body.buyer) {
        errors.push('Müşteri bilgileri gereklidir');
    } else {
        if (!body.buyer.name || body.buyer.name.trim().length < 2) {
            errors.push('Müşteri adı en az 2 karakter olmalıdır');
        }
        if (!body.buyer.surname || body.buyer.surname.trim().length < 2) {
            errors.push('Müşteri soyadı en az 2 karakter olmalıdır');
        }
        if (!body.buyer.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.buyer.email)) {
            errors.push('Geçerli bir e-posta adresi gereklidir');
        }
        if (!body.buyer.phone || !/^[0-9+\s()-]{10,}$/.test(body.buyer.phone.replace(/\s/g, ''))) {
            errors.push('Geçerli bir telefon numarası gereklidir');
        }
    }

    // Fiyat kontrolü
    if (!body.totalPrice || isNaN(body.totalPrice) || parseFloat(body.totalPrice) <= 0) {
        errors.push('Geçerli bir toplam fiyat gereklidir');
    }

    // XSS koruması - basit temizleme
    if (body.buyer) {
        body.buyer.name = sanitizeInput(body.buyer.name);
        body.buyer.surname = sanitizeInput(body.buyer.surname);
        body.buyer.email = sanitizeInput(body.buyer.email);
    }

    return errors;
}

/**
 * Input sanitization fonksiyonu
 */
function sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    return input
        .replace(/[<>]/g, '')
        .trim()
        .substring(0, 255); // Maksimum uzunluk
}

/**
 * POST /api/order/save
 * 
 * Başarılı ödemelerden sonra siparişi veritabanına kaydetmek için
 * (Firebase Firestore ile entegrasyon için hazır)
 */
app.post('/api/order/save', async (req, res) => {
    try {
        const { orderData, paymentResult } = req.body;

        // Loglama
        logPayment('info', paymentResult?.provider || 'unknown', paymentResult?.conversationId || 'unknown', {
            action: 'order_save',
            orderData: orderData,
            paymentResult: paymentResult
        });

        // Burada siparişi Firebase Firestore'a kaydedebilirsiniz
        // Şimdilik sadece log olarak kaydediyoruz
        console.log('Sipariş kaydediliyor:', {
            orderData,
            paymentResult,
            timestamp: new Date().toISOString()
        });

        // TODO: Firebase Firestore'a sipariş kaydet
        // Örnek:
        // await db.collection('siparisler').add({
        //     ...orderData,
        //     paymentResult,
        //     createdAt: firebase.firestore.FieldValue.serverTimestamp(),
        //     status: 'completed'
        // });

        res.json({
            success: true,
            message: 'Sipariş kaydedildi'
        });

    } catch (error) {
        console.error('Sipariş kaydetme hatası:', error);
        logPayment('error', 'unknown', 'unknown', {
            action: 'order_save_error',
            error: error.message
        });
        res.status(500).json({
            error: 'Sipariş kaydedilemedi',
            details: error.message
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        iyzicoConfigured: !!(process.env.IYZICO_API_KEY && process.env.IYZICO_SECRET_KEY),
        paytrConfigured: !!(process.env.PAYTR_MERCHANT_ID && process.env.PAYTR_MERCHANT_KEY && process.env.PAYTR_MERCHANT_SALT),
        https: req.protocol === 'https',
        environment: process.env.NODE_ENV || 'development'
    });
});

// Sunucuyu başlat
app.listen(PORT, () => {
    console.log(`🚀 Ödeme sunucusu ${PORT} portunda çalışıyor`);
    console.log(`📝 İyzico yapılandırması: ${iyzicoConfig.apiKey ? '✓ API Key var' : '✗ API Key yok'}`);
    console.log(`📝 Frontend URL: ${process.env.FRONTEND_URL || 'http://localhost:5500'}`);
});

