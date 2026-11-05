# Satsgate hosted gate: terms of use

**DRAFT. Pending legal review. These terms are not in effect.**

This is a plain-language draft for the closed beta of the hosted gate at `https://gate.satsgate.org`. It is not legal advice. Do not treat it as the agreement you are operating under until a lawyer has reviewed it and a final version is published. Placeholders below (`SATSGATE_TERMS_VERSION`, `SATSGATE_TERMS_URL`, `SATSGATE_ABUSE_CONTACT`) are filled in at deploy. An empty terms version means these words are not the version an account can accept.

## What the hosted gate does

The hosted gate charges for a route and returns a signed receipt. It does not call your origin, relay the buyer's request, or serve your content. The buyer takes the receipt to your origin (`redeem_url`) and repeats the request there. You decide whether that receipt is valid. Satsgate does not monitor what you serve after the receipt is issued, and it does not promise to review your content.

A site is not public until an operator approves it, unless auto-approve is on and the account has passed the origin check and accepted the current terms version. Satsgate can refuse a site, disable one, or suspend an account, without notice. A disabled site stops issuing receipts. Payments already settled are not reversed by that disable. Credits already bought stay on the account. Suspension does not re-enable sites when it is lifted.

The service may change or stop at any time. There is no service level agreement and no promise of uptime.

## Your site

You may register a site only if you own the origin, or you have the right to charge for it. You must follow the law that applies to you and to your buyers.

You may not use the gate for any of the following:

- illegal content or illegal services
- malware, exploits, or other software meant to harm someone
- abuse, including attacks on other people or on Satsgate
- scraping or reselling someone else's API when you do not have the right to do that

Satsgate may disable a site that breaks these rules. Illegal or sanctioned content is prohibited. A site that offers it can be taken down. Satsgate does not undertake to find that content.

## Money

Satsgate does not hold buyer funds. A buyer pays a Lightning invoice. That payment goes to the Lightning Address you set on your account, not to Satsgate.

On the hosted gate, one credit is taken when the receipt is issued. That is when the Lightning invoice is confirmed, or when a USDC payment has settled. The receipt is the thing you paid for. A failed request at your origin does not return the credit. The buyer retries at your origin with the same receipt until it expires or its uses run out. Test mode on Base Sepolia issues a receipt and does not take a credit. It is not a network for real buyers.

A buyer may also pay USDC on Base. That USDC goes to the Base address you verified, or, for a Satsgate credit pack, to Satsgate's treasury address. Satsgate does not hold, forward, or refund that USDC. USDC payments depend on a third-party facilitator. That facilitator can reject a payment. Satsgate does not control that decision, does not complete the payment itself, and does not refund it.

Credits are not money. They are not transferable and they are not redeemable. Credits are not refundable. Any refund from Satsgate, if one is given, is in credits only.

A receipt lasts until `exp`. That is the route's `access_seconds` when you set one, otherwise `SATSGATE_RECEIPT_SECONDS` (default 24 hours), and never longer than 24 hours or the paywall access cap. `uses` is the route's `max_uses`, or 1. After expiry or after the uses are spent, the buyer needs a new payment.

## Satsgate is not your buyer

The sale is between you and the buyer. Satsgate runs the gate that asks for payment and signs the receipt. Satsgate is not a party to the sale of your content, does not set your prices, and does not promise that your origin will answer or that the content is fit for any purpose. The gate is provided as is.

To the extent the law allows, Satsgate is not liable for lost sats, lost credits, lost profits, downtime, or anything a buyer or an origin does. Nothing here limits liability that the law does not let us limit.

## Privacy

Buyers do not get Satsgate accounts. This service is not anonymous. There is no KYC of buyers. An IP address is used to rate-limit that buyer. What is stored for the limit is a hash of a truncated address, not a profile.

When a country list is configured, credit-pack quotes use a local DB-IP Country Lite database to refuse listed countries. That database is © DB-IP, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). https://db-ip.com. The lookup is not used on the gate payment itself. An unknown country is allowed. If the database file is missing while a country list is set, new credit-pack quotes are refused.

EVM payout addresses are checked against a local extract of the OFAC SDN list before they are stored. If that file is missing, the check is skipped and a startup log says the list is missing. A listed address is not stored. An address that later appears on a reloaded list is flagged and the site's USDC rail is turned off.

Payment hashes are stored so a paid invoice can be matched to its receipt. A USDC payment stores the EIP-3009 nonce. The settlement transaction is public on Base. The facilitator may screen addresses. The public directory shows the site name, slug, description, gate URL, and route prices. It does not show the origin secret or the owner.

If you add an email for security alerts, Satsgate stores it only to send the confirmation and those alerts. It is optional. It is not used for marketing and is not shared, except with our email provider (Resend, EU region) to deliver the message. It is not shown in public, not written to logs, and is deleted when you remove it. Without one, Satsgate keeps no email for your account.

Receipts, macaroons, preimages, and payment signatures are not written to logs.

## Changes

This draft will change during legal review. A published version will set `SATSGATE_TERMS_VERSION` to a token and `SATSGATE_TERMS_URL` to the https page. Accepting a newer version is what auto-approve checks. Until that version is published, these words do not bind you or Satsgate.

## Contact

Questions and reports go to the GitHub issues for this repository. Security reports go to GitHub Security Advisories. Abuse reports go to `SATSGATE_ABUSE_CONTACT` when that address is set. When an alert-email address is configured for the service, that address is also the contact in a payout-change email (`SATSGATE_SUPPORT_EMAIL`, `satsgateapp@proton.me` on the hosted service).
