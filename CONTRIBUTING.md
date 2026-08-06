# Discord DNS — Katkıda Bulunma Rehberi (Contributing Guide)

Projemize katkıda bulunmak istediğiniz için teşekkür ederiz! **Discord DNS**, topluluk katkılarıyla büyüyen açık kaynaklı bir yazılımdır.

## 🛠 Nasıl Katkıda Bulunabilirsiniz?

1. **İSS Engelleme İncelemeleri ve Parametre Güncellemeleri**:
   - Superonline, Türk Telekom veya farklı İSS'lerde yaşadığınız yeni engellemeleri bildirebilir veya `dpi_bypass.py` içine yeni bypass parametreleri ekleyebilirsiniz.
2. **Yeni DNS Profilleri**:
   - `dns_manager.py` içine daha düşük ping veren yeni DNS sunucuları önerebilirsiniz.
3. **Hata Bildirimi (Bug Reports)**:
   - Karşılaştığınız hataları GitHub Issues kısmından detaylı şekilde bildirebilirsiniz.

## 🧪 Geliştirici Bağlantı Test Araçları (Diagnostic Testers)

Projeye katkıda bulunurken sistem bağlantı durumunu ve ses bölgesi ping matrisini test etmek için `tests/test_connection.py` teşhis aracını kullanabilirsiniz:

```bash
# Sistem, İSS, Discord uç noktaları ve Ses Bölgesi Ping Matrisini test etmek için:
python tests/test_connection.py
```

## 🚀 Geliştirme Adımları

1. Repoyu çatallayın (Fork edin).
2. Özelliğiniz için yeni bir dal oluşturun: `git checkout -b ozellik/yeni-kanal`.
3. Değişikliklerinizi yapın ve test aracını çalıştırın: `python tests/test_connection.py`.
4. Değişikliklerinizi işleyin (Commit): `git commit -m 'feat: Yeni İSS tünel modu eklendi'`.
5. Dalınıza itin (Push): `git push origin ozellik/yeni-kanal`.
6. Bir Pull Request (PR) açın.

Katkılarınız için şimdiden teşekkürler!
