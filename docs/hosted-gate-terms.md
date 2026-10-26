# Satsgate hosted gate: terms of use

**DRAFT. Pending legal review. These terms are not in effect.**

This is a plain-language draft for the closed beta of the hosted gate at `https://gate.satsgate.org`. It is not legal advice. Do not treat it as the agreement you are operating under until a lawyer has reviewed it and it is published as final.

## Closed beta

The hosted gate is a closed beta. Satsgate may change or stop it at any time. There is no service level agreement and no promise of uptime.

A site is not public until an operator approves it. Satsgate can refuse a site, or disable one that was approved, without notice. A disabled site stops serving. Payments already settled are not reversed by that disable.

## Your site

You may register a site only if you own the origin, or you have the right to put it behind this gate. You must follow the law that applies to you and to your buyers.

You may not use the gate for any of the following:

- illegal content or illegal services
- malware, exploits, or other software meant to harm someone
- abuse, including attacks on other people or on Satsgate
- scraping or reselling someone else's API when you do not have the right to do that

Satsgate may disable a site that breaks these rules. Illegal or sanctioned content is prohibited. A site that offers it can be taken down.

## Money

Satsgate does not hold buyer funds. A buyer pays a Lightning invoice. That payment goes to the Lightning Address you set on your account, not to Satsgate.

One credit is used the first time a paid request is delivered. That is when your origin returns a success (HTTP 2xx) and, for a USDC payment, the facilitator has settled. Later requests that reuse that same payment do not take another credit. If the origin fails, no credit is used and the use is not taken. The buyer can retry with the same macaroon or the same payment signature. A Lightning payment still reaches the Lightning Address on your account when the invoice is paid, which is before the origin runs. Any remedy for a failed origin is between you and the buyer. Satsgate does not refund buyers.

A buyer may also pay USDC on Base. That USDC goes to the Base address you verified, or, for a Satsgate credit pack, to Satsgate's treasury address. Satsgate does not hold, forward, or refund that USDC. USDC payments depend on a third-party facilitator. That facilitator can reject a payment, including after the origin has already run. Satsgate does not control that decision, does not complete the payment itself, and does not refund it.

Credits are not money. They are not transferable and they are not redeemable. Any refund from Satsgate, if one is given, is in credits only.

## Satsgate is not your buyer

The sale is between you and the buyer. Satsgate only runs the gate that asks for payment and then forwards the request. Satsgate is not a party to that sale, does not set your prices, and does not promise that the origin will answer or that the content is fit for any purpose. The gate is provided as is.

To the extent the law allows, Satsgate is not liable for lost sats, lost credits, lost profits, downtime, or anything a buyer or an origin does. Nothing here limits liability that the law does not let us limit.

## Privacy

Buyers do not get Satsgate accounts. This service is not anonymous. An IP address is used to rate-limit that buyer. What is stored for the limit is a hash of a truncated address, not a profile. Payment hashes are stored so a paid invoice can be matched to its grant and its remaining uses. A USDC payment also stores the settlement transaction hash. The transaction itself is public on Base. The facilitator may screen addresses. The public directory shows the site name, slug, description, gate URL, and route prices. It does not show the origin, the origin secret, or the owner.

## Changes

This draft will change during legal review. A final version will say how later changes are announced. Until that version is published, these words do not bind you or Satsgate.

## Contact

Questions and reports go to the GitHub issues for this repository.
