# Beulah Medical Clinic — Advertising Setup

The project is monetization-ready, but advertisements are disabled until you have an approved advertising account.

1. Create/obtain an approved Google AdSense publisher account.
2. Open `public/ads.js`.
3. Set `ADS_ENABLED` to `true`.
4. Replace `PUBLISHER_ID` with your real `ca-pub-...` publisher ID.
5. Replace the two slot IDs with your real ad-unit IDs.
6. Restart the server and hard-refresh the browser.

Ads are placed only on public pages, not inside authenticated patient, staff, doctor or administrator dashboards. The ad script is not given medical-record data.

Important: visits or downloads do not automatically produce income. Revenue depends on the advertising provider, approval, eligible traffic, impressions/clicks and policy compliance. Never sell or pass patient medical information to advertisers.
