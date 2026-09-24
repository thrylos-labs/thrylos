# Wallet safety tool: product spec

Status: **draft for review.** Nothing is built. The name is a placeholder
("Wallet Guard"). Every price, number and choice below is a starting guess to be
tested with real people, not a decision.

## In one paragraph

A browser add-on and a small website that watch out for the mistakes and scams
that cost people crypto: sending to a look-alike address, approving something
they shouldn't, or missing that something odd just happened in their wallet.
Basic warnings are free. Alerts, history and shared team wallets are paid, on a
monthly subscription. It never holds keys or money and cannot move funds.

## Why it exists

The project (Thrylos) needs steady income to pay for a proper security audit.
This is a separate product, aimed at a problem people already have, that can
pay for itself through subscriptions and does not depend on the blockchain
being finished.

## Who it is for

Not everyone. Casual users will not pay, and free tools already cover the
basics for them. It is for people with more at stake:

1. **Serious holders:** someone with a large balance who cannot afford one mistake.
2. **Small teams, clubs and DAOs** who keep shared money in a few wallets and
   want everyone to see what happens to it.
3. **Families:** one person who looks after a parent's or a relative's wallet
   and wants to be told if anything looks wrong.

## The problems it solves

- **Look-alike addresses.** A scammer sends you a tiny amount from an address
  that starts and ends like one you use. Later you copy it from your history and
  send real money to the scammer.
- **Risky approvals.** You click "approve" on a website and give it permission
  to spend your tokens, and forget about it. Months later it is used against you.
- **Not noticing in time.** Something unusual happens in your wallet and you
  find out days later.
- **No second pair of eyes** on a shared team wallet.

## What it does

### Free

- **Address check before you send.** When you paste an address, it says whether
  the address is valid, and warns if it looks very like an address you have
  sent to before, or one that has recently sent you a tiny amount.
- **Shows the full address**, not just the start and end, and asks you to check it.
- **A short "how safe is this wallet" check** you can run once on one wallet.

### Paid: personal

- **Alerts** to email, Telegram or Discord when:
  - something is approved to spend your tokens
  - an amount over a limit you set leaves your wallet
  - you send to an address for the first time
  - a look-alike address appears in your history
- **A list of what you have approved** and which ones to remove.
- **History** of past alerts.
- Up to a small number of wallets to watch.

### Paid: team

- Everything in personal, for **a shared list of wallets**.
- **Several people receive the alerts.**
- **A shared address book** of approved recipients, so a new address stands out.
- More wallets.

## What it will never do

These are promises, written down so nobody can drift from them later:

- It **never asks for your seed phrase or private key**, and it does not need one.
- It **cannot send, sign or move anything.** It only reads public information
  and warns.
- It **does not promise to catch every scam.** It gives warnings, not guarantees,
  and says so everywhere the user can see.
- It **does not sell or share** the list of wallets you watch.

## How it works (in plain terms)

- **The add-on** runs in the browser. The address checks happen on your own
  computer, so your address book and history stay with you.
- **The alerts** need a small server that watches the addresses you choose on
  the blockchain and sends you a message. This is the only part that holds
  something about you (the list of addresses you watch and how to reach you),
  so it keeps only that.
- **The website** is where you sign up, pay, add wallets and see your alerts.
- **The data** comes from public blockchain information, either from a paid
  data provider or from our own nodes.
- **Payments** go through a company that handles cards, tax and refunds for us
  (for example Paddle or Lemon Squeezy), so we never store card details.

## Which blockchains first

Start with **one family: Ethereum and the chains that work like it**, because
that is where most people and most scams are. Add others (Solana, Bitcoin, and
eventually Thrylos) only after people are paying. Thrylos alone has no users
yet, so a tool for it alone would earn nothing.

## Starting prices (to test)

| Plan | Price | For |
|---|---|---|
| Free | $0 | Address checks in the add-on |
| Personal | about $5 a month | One person, a few wallets, alerts |
| Team | about $30 a month | A group, more wallets, shared address book |

These are guesses. The first job is to find out whether anyone pays at all, and
then whether they would pay more.

## What we build first, and what waits

**First version (about four weeks):**
1. The address check and look-alike warning in a browser add-on.
2. Alerts for approvals and large transfers on one blockchain family, to email.
3. A simple sign-up and payment page.

**Later, once people are paying:**
- Telegram and Discord alerts.
- The approvals list and removal suggestions.
- Team plans with a shared address book.
- More blockchains.
- A phone app.

## How we will know it is working

- **Before building:** ten conversations with people in the three groups above.
  At least three say they would pay, and ideally hand over a deposit.
- **After the first version:** **20 paying customers** within two weeks of
  offering it. If we get fewer, we stop or change direction before spending more.
- **After that:** how many people stay subscribed month to month, and how many
  say the alerts told them something they would have missed.

## Risks, and what we do about them

| Risk | What we do |
|---|---|
| A scam gets through and someone loses money | Say plainly that it gives warnings, not guarantees. Have the terms reviewed by a lawyer before launch. |
| People treat it as a reason to be careless | Keep the wording modest. Never say "protected" or "safe". |
| The list of watched wallets is private | Store as little as possible, keep it encrypted, delete it when someone cancels. Publish what we keep. |
| Free tools do the basics already | Charge only for what they do not: alerts, history, teams. Keep the free part good so people trust us. |
| Data costs eat the subscription | Start with one blockchain family and a cap on wallets per plan. Watch the cost per customer from day one. |
| It pulls time from the blockchain | Cap the effort: six weeks, then decide. |
| Rules about running a service that touches crypto | Because it never holds or moves funds, the exposure is smaller than for a wallet or exchange, but get advice for the country the business is in. |

## What it costs to run (rough categories)

Data provider or node hosting, a small server for the alerts, email and
message sending, the payment company's fee, a domain and hosting for the
website, and a lawyer for the terms. The data provider is the one to watch,
since it grows with each watched wallet.

## Six-week plan

| Weeks | What happens |
|---|---|
| 1 | Landing page with a waitlist. Ten conversations. Decide the blockchain and the price to try. |
| 2–4 | Build the first version. Set up payments. |
| 5 | Offer it at a founding price to the waitlist. |
| 6 | Count the paying customers. Continue, change, or stop. |

## Questions to settle before building

1. Which blockchain first? (My suggestion: Ethereum and the chains like it.)
2. Who is it mainly for: serious individuals, teams, or families?
3. How many hours a week can the team give it?
4. Where will the business be registered, and who will review the terms?
5. Should it carry the Thrylos name, or be a separate brand? A separate brand
   keeps a security failure in one from touching the other.
