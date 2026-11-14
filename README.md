# VAfPS (Velocity API for Paper Server)

[![License: GPL v3+](https://img.shields.io/badge/License-GPL%20v3%2B-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Java](https://img.shields.io/badge/java-17%2B-orange.svg)](https://www.oracle.com/java/)
[![Velocity](https://img.shields.io/badge/velocity-3.4.0--SNAPSHOT-informational.svg)](https://papermc.io/software/velocity)

VAfPS, Velocity proxy üzerinde çalışan hafif, güvenli ve yüksek performanslı bir HTTP/1.1 API köprüsüdür. Paper sunucularının veya harici yönetim araçlarının, Velocity seviyesindeki konsol komutlarını doğrudan REST istekleriyle çalıştırmasını ve konsol çıktılarını anlık olarak JSON formatında yakalamasını sağlar.

---

## ⚡ Neden VAfPS?

Geleneksel mimarilerde backend Paper sunucularının Velocity proxy'ye komut iletmesi için şunlar gerekiyordu:
- **Plugin Messaging Channels:** Yalnızca o an çevrimiçi bir oyuncu olduğunda çalışır; oyuncu yoksa paketler iletilemez.
- **Harici Message Broker'lar (RabbitMQ, Redis):** Ekstra sunucu maliyeti, ağ karmaşası ve bakım yükü getirir.

**VAfPS**, harici hiçbir bağımlılık gerektirmeden Java'nın yerleşik HTTP sunucusu üzerinden doğrudan haberleşme sağlar.

---

## 🛡️ Güvenlik Mimarisi

VAfPS kurumsal güvenlik standartları düşünülerek inşa edilmiştir:

- **Soket Seviyesinde CIDR Ağ Kalkanı (Network Shield):** Yetkisiz IP adreslerinden veya yabancı alt ağlardan gelen istekler HTTP seviyesine dahi ulaşmadan reddedilir.
- **Sabit Zamanlı Basic Auth (Timing Attack Koruması):** Kullanıcı adı ve şifre doğrulamaları, zaman analiziyle şifre uzunluğu ve kullanıcı varlığı keşfini (`user enumeration`) önlemek için sabit zamanlı (`MessageDigest.isEqual`) SHA-256 hash karşılaştırmasıyla yapılır.
- **Dinamik Karantina & Tarpit (Brute-Force Shield):** 
  - Bilinen/güvenilir ağlardan gelen başarısız istekler tarpit ile yavaşlatılır.
  - Şüpheli/dış ağlardan gelen ardışık başarısız denemeler geçici karantinaya (`429 Too Many Requests`) alınır.
- **Güvenli İlk Kurulum (PnP Root Protection):** İlk açılışta yerel geliştirme için bir `root` hesabı sunulur; ancak özel bir hesap tanımlandığı anda `root` kalıcı olarak devre dışı bırakılır.
- **Tehlikeli Komut İzolasyonu:** Alias ve root bypass girişimlerine karşı yetki filtreleme mekanizması.
- **Log Temizleyici (Audit Sanitizer):** Konsol günlükleri terminal injection (ANSI kaçış dizileri) saldırılarına karşı temizlenerek audit altına alınır.

---

## 🚀 API Uç Noktaları

### 1. Komut Çalıştırma (`POST /api/v1/command`)
Konsol düzeyinde komut çalıştırır ve çıktısını settle süresiyle yakalar.

**İstek:**
```http
POST /api/v1/command HTTP/1.1
Host: 127.0.0.1:8923
Authorization: Basic cm9vdDpjb25zb2xlX3NlY3JldA==
Content-Type: application/json

{
  "command": "kick Steve Kurallara uyunuz"
}
```

**Yanıt (200 OK):**
```json
{
  "status": "SUCCESS",
  "executed": true,
  "output": [
    "Steve kicked by console."
  ],
  "captureEnabled": true,
  "truncated": false,
  "linesTruncated": false,
  "executionTimeMs": 24
}
```

### 2. Durum Kontrolü (`GET /api/v1/status`)
Servis ve proxy durumunu döner.

```json
{
  "status": "ONLINE",
  "proxy": "Velocity",
  "version": "3.4.0-SNAPSHOT"
}
```

### 3. Sağlık ve Metrik (`GET /api/v1/internal-health`)
İç iş parçacığı kuyruğu ve çalışma süresi metriklerini döner.

```json
{
  "status": "OK",
  "uptimeMs": 3600000,
  "activeWorkers": 2,
  "queueSize": 0
}
```

---

## ⚙️ Gereksinimler & Kurulum

- **Java:** Java 17 veya üzeri
- **Proxy:** Velocity 3.3.0+ / 3.4.0-SNAPSHOT

### Derleme:
```bash
git clone https://github.com/nightmission1/VAfPS.git
cd VAfPS
mvn clean package
```

Derlenen `.jar` dosyasını Velocity sunucunuzun `plugins/` dizinine yerleştirip proxy'yi yeniden başlatmanız yeterlidir.

---

## 🛠️ For Developers (Client SDK)

Paper/Spigot sunucularınızdan veya harici Java uygulamalarınızdan VAfPS API köprüsüne tip güvenli, asenkron ve kolay bir şekilde bağlanmak için resmi Java SDK'sını kullanabilirsiniz:

👉 **[vafps-client-sdk Repository](https://github.com/nightmission1/vafps-client-sdk)**

SDK; bağlantı yönetimi, kimlik doğrulama, rate limiting toleransı ve yanıt ayrıştırma işlemlerini otomatikleştirir.

---

## 📄 Lisans

Bu proje **GNU General Public License v3.0 or later (GPL-v3+)** ile lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakabilirsiniz.

