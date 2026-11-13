# WDBOS REPORT — WBTEAM

Dashboard staff untuk Cloudflare Pages Functions dan Cloudflare D1.

## Deploy
1. Unggah source dashboard (`index.html`, `assets/`, `functions/`, `database/schema.sql`, `wrangler.toml`) ke repository ini.
2. Buat D1 `reportan-wbteam-db` dan jalankan `database/schema.sql`.
3. Hubungkan D1 sebagai binding `DB` di Cloudflare Pages.
4. Hubungkan repository ke Cloudflare Pages dengan nama proyek `reportan-wbteam`.
5. Inisialisasi akun pertama secara privat; jangan commit `database/seed.sql` karena memuat hash password awal yang diketahui.

Target: https://reportan-wbteam.pages.dev
