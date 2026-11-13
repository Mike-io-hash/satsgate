# Satsgate hosted gate: terms of use

Effective date: set at deploy (`SATSGATE_TERMS_VERSION`).

These terms cover the hosted gate at `https://gate.satsgate.org` and the prepaid balance a vendor holds with Satsgate. They are the agreement for that service once `SATSGATE_TERMS_VERSION` is set. If you do not accept a new version, stop using the service.

## What Satsgate is

Satsgate is a 402 gateway. A buyer can pay an invoice in Lightning or USDC. The payment goes to the vendor's own wallet. Satsgate does not take custody of buyer funds, does not split a payment, and does not take a fee from the buyer's payment.

## Accounts

A vendor may open an account without paying and without giving personal data. Email is optional and is used only for security alerts and balance alerts the vendor asked for.

Test mode is free. It does not debit the prepaid balance and it does not use the monthly free quota.

## Live unlocks

Each account has 500 free successful live unlocks per UTC calendar month. Unused free unlocks do not carry over. They reset at 00:00:00 UTC on day 1. Accounts that settle to the same verified EVM address or the same Lightning Address share one monthly quota.

After the free quota, Satsgate charges 2 sats per successful live unlock, capped at 10% of the item. On USDC, until batch settlement exists, the charge is also at least US$0.001. No date is promised for batch settlement. Lightning does not use that floor.

## Prepaid balance

The prepaid balance is a closed-loop credit counted in milisatoshis. It is not money. It is not redeemable for sats, USDC, or fiat. It does not expire. The monthly free quota does expire, as described above.

A top-up has a minimum (1,000 sats on Lightning, US$1 on USDC). A bonus may apply to a single top-up. It is not stacked and it is not based on lifetime volume. If the BTC accounting rate is missing or older than one hour, a USDC top-up is rejected. Lightning top-ups are not.

## Refunds

A refund, when one is given, is a credit to the prepaid balance only. Satsgate does not send sats or USDC back. An automatic credit repairs a debit that should not have happened. A manual credit is for Satsgate's own error, claimed within about 30 days, and reviewed by an operator. There is no refund because the vendor's origin failed after a receipt was issued. Satsgate is not a party to a dispute between a buyer and a vendor.

## Access, sanctions, and receipts

Quotes and signups from Cuba, Iran, and North Korea are refused when that country list is configured. EVM payout addresses are checked against a sanctions list. A receipt lasts up to 24 hours. After it expires, or after its uses are spent, the buyer needs a new payment.

## Privacy

Buyers do not get Satsgate accounts. Satsgate does not collect buyer personal data at signup. An IP address may be used to rate-limit signups and quotes. What is stored for a buyer limit is a hash, not a profile. Logs do not contain API keys, webhook secrets, or preimages.

## Changes

A new version is identified by its effective date in `SATSGATE_TERMS_VERSION`. If you do not accept it, stop using the service.
