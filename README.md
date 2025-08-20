# 🛡️ SolidityGuard - Akıllı Kontrat Güvenlik Analizi

[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/darksoftinc/intelligent-contract-security)
[![Security](https://img.shields.io/badge/Security-Audit%20Ready-yellow.svg)](https://github.com/darksoftinc/intelligent-contract-security)

> **SolidityGuard**, Solidity akıllı kontratlarında güvenlik açıklarını otomatik olarak tespit eden gelişmiş bir güvenlik analiz aracıdır. Rust ile geliştirilmiş backend ve modern web arayüzü ile profesyonel güvenlik denetimi sağlar.

## 🚀 Özellikler

### 🔍 **Gelişmiş Zafiyet Tespiti**
- **Reentrancy Saldırıları** - Kritik seviye güvenlik açığı
- **Integer Overflow/Underflow** - Sayısal taşma tespiti
- **Access Control** - Yetki kontrolü eksiklikleri
- **Unchecked External Calls** - Kontrolsüz dış çağrılar
- **Gas Optimization** - Gaz optimizasyonu sorunları
- **Timestamp Dependence** - Zaman damgası bağımlılıkları
- **Weak Randomness** - Zayıf rastgelelik kaynakları
- **Storage vs Memory** - Depolama bellek karışıklıkları
- **Constructor Issues** - Yapıcı fonksiyon sorunları
- **Fallback Function** - Geri dönüş fonksiyonu güvenlik açıkları

### 🎯 **Akıllı Analiz Sistemi**
- **Gerçek Zamanlı Tarama** - Anında sonuç
- **Güvenlik Skoru** - 0-100 arası otomatik hesaplama
- **Risk Seviyesi Belirleme** - Kritik, Yüksek, Orta, Düşük
- **Detaylı Raporlama** - JSON formatında kapsamlı çıktı
- **CWE Entegrasyonu** - Standart güvenlik açığı kategorileri

### 🌐 **Modern Web Arayüzü**
- **Responsive Tasarım** - Mobil ve masaüstü uyumlu
- **Tailwind CSS** - Modern ve şık görünüm
- **Drag & Drop** - Kolay dosya yükleme
- **Gerçek Zamanlı İstatistikler** - Analiz metrikleri
- **Görsel Güvenlik Skoru** - Dairesel progress bar
- **Zafiyet Badge'leri** - Severity'ye göre renkli gösterim

## 📋 Gereksinimler

- **Rust** 1.75+ ([Rust Kurulum](https://rustup.rs/))
- **Cargo** (Rust ile birlikte gelir)
- **Modern Web Tarayıcısı** (Chrome, Firefox, Safari, Edge)

## 🛠️ Kurulum

### 1. Projeyi Klonlayın
```bash
git clone https://github.com/darksoftinc/intelligent-contract-security.git
cd intelligent-contract-security
```

### 2. Bağımlılıkları Yükleyin
```bash
cargo build
```

### 3. Uygulamayı Çalıştırın
```bash
cargo run
```

### 4. Web Arayüzünü Açın
Tarayıcınızda `http://127.0.0.1:3000` adresini açın.

## 🎮 Kullanım

### **Web Arayüzü ile Analiz**
1. **Dosya Yükleme**: `.sol` uzantılı Solidity dosyasını sürükleyin
2. **Kod Yapıştırma**: Doğrudan kod yapıştırın
3. **Analiz Başlatma**: "Analiz Et" butonuna tıklayın
4. **Sonuçları İnceleme**: JSON formatında detaylı rapor alın

### **Komut Satırı ile Analiz**
```bash
# Tek dosya analizi
cargo run -- path/to/contract.sol

# Çoklu dosya analizi
for file in contracts/*.sol; do
    cargo run -- "$file"
done
```

### **API Kullanımı**
```bash
# POST isteği ile analiz
curl -X POST http://127.0.0.1:3000/analyze \
  -H "Content-Type: text/plain" \
  --data-binary @contract.sol
```

## 📊 Örnek Çıktı

```json
{
  "vulnerabilities": [
    {
      "name": "Reentrancy Attack",
      "line_number": 25,
      "description": "External call with value transfer before state update",
      "severity": "Critical",
      "category": "Reentrancy",
      "recommendation": "Use ReentrancyGuard modifier",
      "cwe_id": "CWE-841",
      "impact": "Funds can be drained through recursive calls"
    }
  ],
  "summary": {
    "total_vulnerabilities": 1,
    "critical_count": 1,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "security_score": 70,
    "risk_level": "High Risk"
  },
  "metadata": {
    "solidity_version": "pragma solidity ^0.8.20",
    "contract_count": 2,
    "function_count": 8,
    "line_count": 45,
    "analysis_time": 0.023
  }
}
```

## 🏗️ Proje Yapısı

```
intelligent-contract-security/
├── src/
│   ├── main.rs              # Ana uygulama ve HTTP sunucu
│   └── analysis/
│       └── mod.rs           # Zafiyet analiz motoru
├── web/
│   └── index.html           # Web arayüzü
├── vulnerable_samples/       # Test için zafiyetli örnekler
├── Cargo.toml               # Rust bağımlılıkları
└── README.md                # Bu dosya
```

## 🔧 Teknik Detaylar

### **Backend (Rust)**
- **Actix Web** - Yüksek performanslı HTTP sunucu
- **Serde** - JSON serileştirme/deserileştirme
- **Modüler Mimari** - Genişletilebilir analiz sistemi

### **Frontend (Web)**
- **Vanilla JavaScript** - Modern ES6+ özellikleri
- **Tailwind CSS** - Utility-first CSS framework
- **Font Awesome** - Profesyonel ikonlar
- **Responsive Design** - Tüm cihazlarda uyumlu

### **Güvenlik Algoritmaları**
- **Pattern Matching** - Regex tabanlı tespit
- **Context Analysis** - Kod bağlamı analizi
- **Severity Scoring** - Otomatik risk değerlendirmesi
- **CWE Mapping** - Standart güvenlik kategorileri

## 🧪 Test Örnekleri

Proje içinde `vulnerable_samples/` klasöründe test edebileceğiniz örnekler:

- **ReentrancyBank.sol** - Reentrancy saldırısı örneği
- **IntegerOverflowLegacy.sol** - Integer overflow örneği
- **TxOriginAuth.sol** - tx.origin kullanım hatası
- **SelfDestruct.sol** - Kontrolsüz selfdestruct
- **SendEtherIgnore.sol** - Unchecked send kullanımı

## 📈 Performans

- **Analiz Hızı**: ~1000 satır/saniye
- **Bellek Kullanımı**: <50MB
- **CPU Kullanımı**: Minimal
- **Yanıt Süresi**: <100ms (ortalama)

## 🤝 Katkıda Bulunma

1. **Fork** yapın
2. **Feature branch** oluşturun (`git checkout -b feature/AmazingFeature`)
3. **Commit** yapın (`git commit -m 'Add some AmazingFeature'`)
4. **Push** yapın (`git push origin feature/AmazingFeature`)
5. **Pull Request** oluşturun

### **Geliştirme Kurulumu**
```bash
# Geliştirme bağımlılıkları
cargo install cargo-watch
cargo install cargo-tarpaulin  # Test coverage

# Geliştirme sunucusu (otomatik yeniden yükleme)
cargo watch -x run
```

## 🐛 Hata Bildirimi

- **GitHub Issues** kullanarak hata bildirin
- **Reproducible** örnekler ekleyin
- **Environment** bilgilerini paylaşın
- **Expected vs Actual** davranışı belirtin

## 📄 Lisans

Bu proje **MIT License** altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 🙏 Teşekkürler

- **Rust Community** - Mükemmel dil ve ekosistem
- **Actix Web** - Yüksek performanslı web framework
- **Tailwind CSS** - Modern CSS framework
- **Open Source Community** - Sürekli ilham ve destek

## 📞 İletişim

- **GitHub**: [@darksoftinc](https://github.com/darksoftinc)
- **Proje**: [intelligent-contract-security](https://github.com/darksoftinc/intelligent-contract-security)
- **Issues**: [GitHub Issues](https://github.com/darksoftinc/intelligent-contract-security/issues)

## 🌟 Yıldız Verin

Bu proje size yardımcı olduysa, GitHub'da ⭐ yıldız vermeyi unutmayın!

---

**SolidityGuard** ile akıllı kontratlarınızı güvenli hale getirin! 🚀
